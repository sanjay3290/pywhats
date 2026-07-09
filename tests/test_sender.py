# SPDX-License-Identifier: Apache-2.0
"""Unit tests for :mod:`pywhats.messaging.sender`.

The transport and the frame-reader are both mocked. Signal crypto is
exercised for real - a responder-side ratchet is initialised alongside
the sender and used to decrypt what the sender ships, so the binary
stanza and its payload are validated end-to-end without touching a
real socket.
"""

from __future__ import annotations

import asyncio
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import pytest

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.binary import decode  # noqa: E402
from pywhats.events import JID  # noqa: E402
from pywhats.messaging import (  # noqa: E402
    AckRouter,
    Sender,
    SenderConfig,
    UserSyncEntry,
    new_message_id,
)
from pywhats.messaging.addressing import session_id  # noqa: E402
from pywhats.messaging.ids import _reset_for_tests  # noqa: E402
from pywhats.messaging.router import RetrySignal  # noqa: E402
from pywhats.proto import Message as MessageProto  # noqa: E402
from pywhats.signal.experimental import (  # noqa: E402
    IdentityKeyPair,
    InMemoryIdentityStore,
    InMemoryLidMap,
    InMemorySessionStore,
    PreKeyBundle,
    SignedPreKey,
    generate_pre_key,
    ratchet_decrypt,
    ratchet_init_bob,
    x3dh_responder,
)
from pywhats.signal.experimental.types import PreKeySignalMessage  # noqa: E402

# --- fake transport --------------------------------------------------


class FakeTransport:
    """Collects frames written by the sender."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self._delay: float = 0.0

    def with_delay(self, delay: float) -> FakeTransport:
        self._delay = delay
        return self

    async def send(self, plaintext: bytes) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        self.frames.append(plaintext)


@dataclass(frozen=True)
class FakeIdentity:
    identity_private: bytes
    identity_public: bytes
    registration_id: int


# --- test rig --------------------------------------------------------


def _make_bob_bundle() -> tuple[IdentityKeyPair, SignedPreKey, Any, PreKeyBundle]:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=7)
    bob_opk = generate_pre_key(key_id=123)
    bundle = PreKeyBundle(
        identity_key=bob_ik.public,
        signed_pre_key_id=bob_spk.key_id,
        signed_pre_key_public=bob_spk.public,
        signed_pre_key_signature=bob_spk.signature,
        one_time_pre_key_id=bob_opk.key_id,
        one_time_pre_key_public=bob_opk.public,
    )
    return bob_ik, bob_spk, bob_opk, bundle


def _build_sender(
    *,
    transport: FakeTransport,
    router: AckRouter,
    bundle: PreKeyBundle,
    ack_timeout: float = 1.0,
) -> tuple[Sender, FakeIdentity]:
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )

    async def fetcher(_peer: JID) -> PreKeyBundle:
        return bundle

    sender = Sender(
        transport=transport,
        router=router,
        session_store=InMemorySessionStore(),
        identity=identity,
        prekey_fetcher=fetcher,
        own_jid=JID(user="15550001111", server="s.whatsapp.net"),
        config=SenderConfig(ack_timeout_seconds=ack_timeout),
    )
    return sender, identity


# --- tests -----------------------------------------------------------


def setup_function() -> None:
    _reset_for_tests()


def test_new_message_id_shape_and_uniqueness() -> None:
    seen: set[str] = set()
    for _ in range(50):
        mid = new_message_id()
        assert len(mid) == 16
        assert mid == mid.upper()
        int(mid, 16)  # hex parses
        assert mid not in seen
        seen.add(mid)


@pytest.mark.asyncio
async def test_send_text_builds_expected_stanza_and_roundtrips() -> None:
    transport = FakeTransport()
    router = AckRouter()
    bob_ik, bob_spk, bob_opk, bundle = _make_bob_bundle()
    sender, alice_identity = _build_sender(transport=transport, router=router, bundle=bundle)
    chat = JID(user="15557654321", server="s.whatsapp.net")

    send_task = asyncio.create_task(sender.send_text(chat, "hello from pywhats"))

    # Wait until the sender has actually shipped the frame.
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    assert transport.frames, "sender did not write a frame"

    (message_id,) = router.pending_ids()
    router.resolve_ack(message_id)
    result = await send_task

    assert result.id == message_id
    assert result.from_me is True
    assert result.text == "hello from pywhats"
    assert result.chat == chat

    # Inspect the binary stanza.
    frame = transport.frames[0]
    stanza = decode(frame)
    assert stanza.tag == "message"
    assert stanza.get_str("id") == message_id
    assert stanza.get_str("type") == "text"
    to_attr = stanza.attrs["to"]
    assert isinstance(to_attr, JID)
    assert to_attr.user == chat.user

    participants = stanza.get_child("participants")
    assert participants is not None
    to_node = participants.get_child("to")
    assert to_node is not None
    enc = to_node.get_child("enc")
    assert enc is not None
    assert enc.get_str("v") == "2"
    # First message in a new session -> pkmsg.
    assert enc.get_str("type") == "pkmsg"

    ciphertext = enc.content_bytes()
    assert b"hello from pywhats" not in ciphertext

    # Responder-side decrypt: decode the PreKeySignalMessage and run
    # x3dh_responder + ratchet_init_bob + ratchet_decrypt to recover
    # the plaintext protobuf.
    pkmsg = PreKeySignalMessage.decode(ciphertext)
    assert pkmsg.one_time_pre_key_id == bundle.one_time_pre_key_id
    assert pkmsg.signed_pre_key_id == bundle.signed_pre_key_id

    br = x3dh_responder(bob_ik, bob_spk, bob_opk, pkmsg.identity_key, pkmsg.base_key)
    bob_state = ratchet_init_bob(br.shared_secret, bob_spk.private, bob_spk.public)
    ad = alice_identity.identity_public + bob_ik.public
    plaintext = ratchet_decrypt(
        bob_state,
        pkmsg.message.header,
        pkmsg.message.ciphertext,
        ad,
        verify_mac=lambda mac_key: pkmsg.message.verify_mac(
            alice_identity.identity_public,
            bob_ik.public,
            mac_key,
        ),
    )
    from pywhats.messaging.padding import unpad_random_max16

    proto = MessageProto()
    proto.ParseFromString(unpad_random_max16(plaintext))
    assert proto.conversation == "hello from pywhats"


@pytest.mark.asyncio
async def test_send_text_fans_out_to_recipient_and_own_devices() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )
    own_jid = JID(user="15550001111", server="s.whatsapp.net", device=3)
    chat = JID(user="15557654321", server="s.whatsapp.net")

    async def fetcher(_peer: JID) -> PreKeyBundle:
        return bundle

    async def devices(_users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        return {
            chat: UserSyncEntry(
                devices=[
                    JID(user=chat.user, server=chat.server, device=0),
                    JID(user=chat.user, server=chat.server, device=12),
                ]
            ),
            JID(user=own_jid.user, server=own_jid.server): UserSyncEntry(
                devices=[
                    JID(user=own_jid.user, server=own_jid.server, device=3),
                    JID(user=own_jid.user, server=own_jid.server, device=9),
                ]
            ),
        }

    sender = Sender(
        transport=transport,
        router=router,
        session_store=InMemorySessionStore(),
        identity=identity,
        prekey_fetcher=fetcher,
        device_fetcher=devices,
        adv_signed_device_identity=b"adv",
        own_jid=own_jid,
        config=SenderConfig(ack_timeout_seconds=1.0),
    )

    task = asyncio.create_task(sender.send_text(chat, "fanout"))
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_ack(router.pending_ids()[0])
    await task

    stanza = decode(transport.frames[0])
    participants = stanza.get_child("participants")
    assert participants is not None
    sent_to = [node.attrs["jid"] for node in participants.get_children("to")]
    assert sent_to == [
        JID(user=chat.user, server=chat.server, device=0),
        JID(user=chat.user, server=chat.server, device=12),
        JID(user=own_jid.user, server=own_jid.server, device=9),
    ]
    assert stanza.get_child("device-identity") is not None


def _decrypt_pkmsg_node(
    enc_node: Any,
    bob_ik: IdentityKeyPair,
    bob_spk: SignedPreKey,
    bob_opk: Any,
    alice_public: bytes,
) -> MessageProto:
    """Responder-side decrypt of one participant ``<enc type=pkmsg>``."""
    from pywhats.messaging.padding import unpad_random_max16
    from pywhats.signal.experimental import ratchet_decrypt as _decrypt

    pkmsg = PreKeySignalMessage.decode(enc_node.content_bytes())
    br = x3dh_responder(bob_ik, bob_spk, bob_opk, pkmsg.identity_key, pkmsg.base_key)
    state = ratchet_init_bob(br.shared_secret, bob_spk.private, bob_spk.public)
    ad = alice_public + bob_ik.public
    plaintext = _decrypt(
        state,
        pkmsg.message.header,
        pkmsg.message.ciphertext,
        ad,
        verify_mac=lambda mac_key: pkmsg.message.verify_mac(
            alice_public,
            bob_ik.public,
            mac_key,
        ),
    )
    proto = MessageProto()
    proto.ParseFromString(unpad_random_max16(plaintext))
    return proto


@pytest.mark.asyncio
async def test_own_device_copy_is_wrapped_in_device_sent_message() -> None:
    """Issue: the copy fanned out to our own devices must be a DSM wrapper.

    The peer's device decrypts to the bare original ``Message``; our own
    other device decrypts to ``Message { device_sent_message {
    destination_jid: <peer>, message: <original> } }`` so it renders the
    message as outgoing in the chat's sent view.
    """
    transport = FakeTransport()
    router = AckRouter()
    bob_ik, bob_spk, bob_opk, bundle = _make_bob_bundle()
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )
    own_jid = JID(user="15550001111", server="s.whatsapp.net", device=3)
    chat = JID(user="15557654321", server="s.whatsapp.net")
    own_other_device = JID(user=own_jid.user, server=own_jid.server, device=9)

    async def fetcher(_peer: JID) -> PreKeyBundle:
        return bundle

    async def devices(_users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        return {
            chat: UserSyncEntry(devices=[chat]),
            JID(user=own_jid.user, server=own_jid.server): UserSyncEntry(
                devices=[own_jid, own_other_device]
            ),
        }

    sender = Sender(
        transport=transport,
        router=router,
        session_store=InMemorySessionStore(),
        identity=identity,
        prekey_fetcher=fetcher,
        device_fetcher=devices,
        own_jid=own_jid,
        config=SenderConfig(ack_timeout_seconds=1.0),
    )

    task = asyncio.create_task(sender.send_text(chat, "dsm test"))
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_ack(router.pending_ids()[0])
    await task

    stanza = decode(transport.frames[0])
    participants = stanza.get_child("participants")
    assert participants is not None
    nodes = {node.attrs["jid"]: node.get_child("enc") for node in participants.get_children("to")}
    assert set(nodes) == {chat, own_other_device}

    peer_proto = _decrypt_pkmsg_node(
        nodes[chat], bob_ik, bob_spk, bob_opk, identity.identity_public
    )
    assert peer_proto.conversation == "dsm test"
    assert not peer_proto.HasField("device_sent_message")

    own_proto = _decrypt_pkmsg_node(
        nodes[own_other_device], bob_ik, bob_spk, bob_opk, identity.identity_public
    )
    assert own_proto.HasField("device_sent_message")
    dsm = own_proto.device_sent_message
    assert dsm.destination_jid == "15557654321@s.whatsapp.net"
    assert dsm.message.conversation == "dsm test"
    assert not dsm.message.HasField("device_sent_message")


@pytest.mark.asyncio
async def test_retry_receipt_from_own_device_resends_dsm_wrapper() -> None:
    """A retry from our own other device must re-encrypt the DSM copy."""
    transport = FakeTransport()
    router = AckRouter()
    bob_ik, bob_spk, bob_opk, bundle = _make_bob_bundle()
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )
    own_jid = JID(user="15550001111", server="s.whatsapp.net", device=3)
    chat = JID(user="15557654321", server="s.whatsapp.net")
    own_other_device = JID(user=own_jid.user, server=own_jid.server, device=9)

    async def fetcher(_peer: JID) -> PreKeyBundle:
        return bundle

    async def devices(_users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        return {
            chat: UserSyncEntry(devices=[chat]),
            JID(user=own_jid.user, server=own_jid.server): UserSyncEntry(
                devices=[own_jid, own_other_device]
            ),
        }

    sender = Sender(
        transport=transport,
        router=router,
        session_store=InMemorySessionStore(),
        identity=identity,
        prekey_fetcher=fetcher,
        device_fetcher=devices,
        own_jid=own_jid,
        config=SenderConfig(ack_timeout_seconds=1.0),
    )

    task = asyncio.create_task(sender.send_text(chat, "retry dsm"))
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    message_id = router.pending_ids()[0]
    router.resolve_ack(message_id)
    await task

    retry_task = asyncio.create_task(
        sender.handle_retry_receipt(message_id, own_other_device, bundle, count=1)
    )
    for _ in range(50):
        if len(transport.frames) >= 2 and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_ack(message_id)
    await retry_task

    stanza = decode(transport.frames[1])
    participants = stanza.get_child("participants")
    assert participants is not None
    (to_node,) = participants.get_children("to")
    assert to_node.attrs["jid"] == own_other_device
    proto = _decrypt_pkmsg_node(
        to_node.get_child("enc"), bob_ik, bob_spk, bob_opk, identity.identity_public
    )
    assert proto.HasField("device_sent_message")
    assert proto.device_sent_message.destination_jid == "15557654321@s.whatsapp.net"
    assert proto.device_sent_message.message.conversation == "retry dsm"


@pytest.mark.skip(
    reason="Outbound PN->LID resolution is temporarily disabled — live test "
    "showed LID-keyed outbound silently dropped on delivery. Inbound LID "
    "remains supported. Re-enable when we figure out what extra glue WA "
    "wants for LID-keyed outbound."
)
@pytest.mark.asyncio
async def test_resolve_signal_address_usyncs_caches_and_migrates_pn_session() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )
    pn = JID(user="15551234567", server="s.whatsapp.net", device=12)
    lid = JID(user="111222333444555", server="lid", device=12)
    base_pn = JID(user=pn.user, server=pn.server)
    calls: list[list[JID]] = []

    async def fetcher(_peer: JID) -> PreKeyBundle:
        return bundle

    async def devices(users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        requested = list(users)
        calls.append(requested)
        return {base_pn: UserSyncEntry(devices=[base_pn], lid=JID(user=lid.user, server="lid"))}

    sessions = InMemorySessionStore()
    identities = InMemoryIdentityStore()
    lid_map = InMemoryLidMap()
    sender = Sender(
        transport=transport,
        router=router,
        session_store=sessions,
        identity=identity,
        prekey_fetcher=fetcher,
        device_fetcher=devices,
        identity_store=identities,
        lid_map=lid_map,
        own_jid=JID(user="15550001111", server="s.whatsapp.net"),
        config=SenderConfig(ack_timeout_seconds=1.0),
    )
    state, meta = sender._establish_session_from_bundle(bundle)
    sessions.save(session_id(pn), state)
    identities.save(session_id(pn), meta.peer_identity)

    assert await sender._resolve_signal_address(pn) == lid
    assert lid_map.get_lid(pn.user) == lid.user
    assert sessions.load(session_id(pn)) is None
    assert identities.load(session_id(pn)) is None
    assert sessions.load(session_id(lid)) is not None
    assert identities.load(session_id(lid)) == meta.peer_identity

    assert await sender._resolve_signal_address(pn) == lid
    assert calls == [[base_pn]]


@pytest.mark.skip(
    reason="Outbound PN->LID resolution is temporarily disabled (see "
    "_resolve_signal_address). Inbound LID handling remains tested."
)
@pytest.mark.asyncio
async def test_encrypt_for_peer_uses_lid_signal_address_after_usync() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    alice_ik = IdentityKeyPair.generate()
    identity = FakeIdentity(
        identity_private=alice_ik.private,
        identity_public=alice_ik.public,
        registration_id=9991,
    )
    pn = JID(user="15551234567", server="s.whatsapp.net", device=7)
    base_pn = JID(user=pn.user, server=pn.server)
    lid = JID(user="111222333444555", server="lid", device=7)
    fetched_prekeys: list[JID] = []
    fetched_devices = 0

    async def fetcher(peer: JID) -> PreKeyBundle:
        fetched_prekeys.append(peer)
        return bundle

    async def devices(_users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        nonlocal fetched_devices
        fetched_devices += 1
        return {base_pn: UserSyncEntry(devices=[base_pn], lid=JID(user=lid.user, server="lid"))}

    sender = Sender(
        transport=transport,
        router=router,
        session_store=InMemorySessionStore(),
        identity=identity,
        prekey_fetcher=fetcher,
        device_fetcher=devices,
        own_jid=JID(user="15550001111", server="s.whatsapp.net"),
        config=SenderConfig(ack_timeout_seconds=1.0),
    )

    enc_type, ciphertext = await sender._encrypt_for_peer(pn, b"hello")

    assert enc_type == "pkmsg"
    assert ciphertext
    assert fetched_prekeys == [lid]
    assert fetched_devices == 1


@pytest.mark.asyncio
async def test_concurrent_sends_resolve_independently() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    sender, _ = _build_sender(transport=transport, router=router, bundle=bundle)

    chat_a = JID(user="15551111111", server="s.whatsapp.net")
    chat_b = JID(user="15552222222", server="s.whatsapp.net")

    task_a = asyncio.create_task(sender.send_text(chat_a, "alpha"))
    task_b = asyncio.create_task(sender.send_text(chat_b, "beta"))

    # Wait for both to register.
    for _ in range(100):
        if len(router.pending_ids()) == 2 and len(transport.frames) == 2:
            break
        await asyncio.sleep(0.01)
    assert len(router.pending_ids()) == 2

    # Resolve the second one first; both futures should still complete cleanly.
    ids = router.pending_ids()
    router.resolve_ack(ids[1])
    router.resolve_ack(ids[0])
    a, b = await asyncio.gather(task_a, task_b)
    assert {a.id, b.id} == set(ids)
    assert a.id != b.id


@pytest.mark.asyncio
async def test_timeout_raises_and_cleans_up() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    sender, _ = _build_sender(transport=transport, router=router, bundle=bundle, ack_timeout=0.05)

    with pytest.raises(TimeoutError):
        await sender.send_text(JID(user="15553334444", server="s.whatsapp.net"), "lost")

    assert router.pending_ids() == []


@pytest.mark.asyncio
async def test_retry_triggers_one_resend_then_succeeds() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    sender, _ = _build_sender(transport=transport, router=router, bundle=bundle)

    chat = JID(user="15559998888", server="s.whatsapp.net")
    task = asyncio.create_task(sender.send_text(chat, "retry-me"))

    # First send.
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    first_id = router.pending_ids()[0]
    router.resolve_retry(first_id, attrs={"count": "1"})

    # Sender should immediately reissue the same logical message (new
    # Signal session, same message id).
    for _ in range(50):
        if len(transport.frames) >= 2 and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    assert len(transport.frames) == 2
    second_id = router.pending_ids()[0]
    assert second_id == first_id

    router.resolve_ack(second_id)
    result = await task
    assert result.id == first_id


@pytest.mark.asyncio
async def test_retry_receipt_resends_only_failed_device_with_count() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    sender, _ = _build_sender(transport=transport, router=router, bundle=bundle)

    chat = JID(user="15559998888", server="s.whatsapp.net")
    task = asyncio.create_task(sender.send_text(chat, "retry-receipt"))
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    message_id = router.pending_ids()[0]
    router.resolve_ack(message_id)
    await task

    failed_device = JID(user=chat.user, server=chat.server, device=12)
    retry_task = asyncio.create_task(
        sender.handle_retry_receipt(message_id, failed_device, bundle, count=1)
    )
    for _ in range(50):
        if len(transport.frames) >= 2 and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_ack(message_id)
    await retry_task

    stanza = decode(transport.frames[1])
    participants = stanza.get_child("participants")
    assert participants is not None
    nodes = participants.get_children("to")
    assert len(nodes) == 1
    assert nodes[0].attrs["jid"] == failed_device
    enc = nodes[0].get_child("enc")
    assert enc is not None
    assert enc.get_str("count") == "1"


@pytest.mark.asyncio
async def test_second_retry_surfaces_as_error() -> None:
    transport = FakeTransport()
    router = AckRouter()
    _, _, _, bundle = _make_bob_bundle()
    sender, _ = _build_sender(transport=transport, router=router, bundle=bundle)

    task = asyncio.create_task(
        sender.send_text(JID(user="15550000000", server="s.whatsapp.net"), "double-retry")
    )
    for _ in range(50):
        if transport.frames and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_retry(router.pending_ids()[0], attrs={})

    for _ in range(50):
        if len(transport.frames) >= 2 and router.pending_ids():
            break
        await asyncio.sleep(0.01)
    router.resolve_retry(router.pending_ids()[0], attrs={})

    with pytest.raises(RuntimeError):
        await task


def test_retry_signal_dataclass() -> None:
    sig = RetrySignal(attrs={"count": "1"})
    assert sig.attrs == {"count": "1"}


def test_build_usync_node_has_expected_shape() -> None:
    peer = JID(user="15550101010", server="s.whatsapp.net")
    node = Sender.build_usync_node("ABCDEF0123456789", peer)
    assert node.tag == "iq"
    assert node.get_str("id") == "ABCDEF0123456789"
    assert node.get_str("type") == "get"
    assert node.get_str("xmlns") == "usync"
    usync = node.get_child("usync")
    assert usync is not None
    assert usync.get_str("mode") == "query"
    query = usync.get_child("query")
    assert query is not None
    assert query.get_child("lid") is not None
