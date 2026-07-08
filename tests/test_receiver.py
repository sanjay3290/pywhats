# SPDX-License-Identifier: Apache-2.0
"""Unit tests for :mod:`pywhats.messaging.receiver`.

The Noise transport is mocked with an asyncio queue on either side. The
peer's Signal crypto runs for real: we drive a sender-side ratchet
locally to produce a pkmsg (first message in a new session) and a plain
msg (subsequent message), then feed both frames to the receiver and
assert that the decrypted ``Message`` dataclass is emitted and that a
matching ``<receipt>`` is written back to the transport.
"""

from __future__ import annotations

import asyncio
import warnings
from dataclasses import dataclass

import pytest

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.binary import Node, decode, encode  # noqa: E402
from pywhats.errors import ConnectionClosed  # noqa: E402
from pywhats.events import JID, Message  # noqa: E402
from pywhats.messaging import AckRouter, PendingIqMap, Receiver  # noqa: E402
from pywhats.messaging.addressing import session_id  # noqa: E402
from pywhats.proto import Message as MessageProto  # noqa: E402
from pywhats.signal.experimental import (  # noqa: E402
    IdentityKeyPair,
    InMemoryLidMap,
    InMemorySessionStore,
    PreKeyBundle,
    SignedPreKey,
    generate_pre_key,
    ratchet_encrypt,
    ratchet_init_alice,
    x3dh_initiator,
)
from pywhats.signal.experimental.keys import (  # noqa: E402
    OneTimePreKey,
    signal_pubkey,
)
from pywhats.signal.experimental.types import (  # noqa: E402
    MessageHeader,
    PreKeySignalMessage,
    SignalMessage,
)

# --- mock transport --------------------------------------------------


class FakeTransport:
    """Asyncio-queue-backed mock for :class:`NoiseTransport`.

    The test writes decrypted-Noise *plaintext* frames into ``inbound``
    and the receiver consumes them via ``recv``. Outbound stanzas from
    the receiver are appended to ``outbound_frames`` (already encoded
    binary-node bytes).
    """

    def __init__(self) -> None:
        self.inbound: asyncio.Queue[bytes | BaseException] = asyncio.Queue()
        self.outbound_frames: list[bytes] = []

    async def recv(self) -> bytes:
        item = await self.inbound.get()
        if isinstance(item, BaseException):
            raise item
        return item

    async def send(self, plaintext: bytes) -> None:
        self.outbound_frames.append(plaintext)


@dataclass
class FakeResponderIdentity:
    identity_private: bytes
    identity_public: bytes
    _spk: SignedPreKey
    _opks: dict[int, OneTimePreKey]

    def get_signed_pre_key(self, key_id: int) -> SignedPreKey:
        if key_id != self._spk.key_id:
            raise ValueError(f"unknown spk id {key_id}")
        return self._spk

    def get_one_time_pre_key(self, key_id: int) -> OneTimePreKey | None:
        return self._opks.get(key_id)


@dataclass
class FakeRetryHandler:
    calls: list[tuple[str, JID, PreKeyBundle | None, int]]

    async def handle_retry_receipt(
        self,
        message_id: str,
        peer: JID,
        bundle: PreKeyBundle | None = None,
        count: int = 1,
    ) -> None:
        self.calls.append((message_id, peer, bundle, count))


# --- per-test rig helpers -------------------------------------------


def _bob_side() -> FakeResponderIdentity:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=7)
    bob_opk = generate_pre_key(key_id=123)
    return FakeResponderIdentity(
        identity_private=bob_ik.private,
        identity_public=bob_ik.public,
        _spk=bob_spk,
        _opks={bob_opk.key_id: bob_opk},
    )


def _make_peer_pkmsg(
    bob: FakeResponderIdentity, text: str
) -> tuple[bytes, IdentityKeyPair, object, bytes]:
    return _make_peer_pkmsg_proto(bob, MessageProto(conversation=text))


def _make_peer_pkmsg_proto(
    bob: FakeResponderIdentity, message_proto: MessageProto
) -> tuple[bytes, IdentityKeyPair, object, bytes]:
    """Produce a pkmsg ciphertext as if an external Alice sent one.

    Returns ``(ciphertext, alice_identity, alice_state, ad)`` — the
    ratchet state is returned so a follow-up plain ``msg`` can be
    produced for the established-session test.
    """
    alice_ik = IdentityKeyPair.generate()
    bundle = PreKeyBundle(
        identity_key=bob.identity_public,
        signed_pre_key_id=bob._spk.key_id,
        signed_pre_key_public=bob._spk.public,
        signed_pre_key_signature=bob._spk.signature,
        one_time_pre_key_id=list(bob._opks.keys())[0],
        one_time_pre_key_public=list(bob._opks.values())[0].public,
    )
    result = x3dh_initiator(alice_ik, bundle)
    state = ratchet_init_alice(result.shared_secret, bundle.signed_pre_key_public)
    ad = alice_ik.public + bob.identity_public
    from pywhats.messaging.padding import pad_random_max16

    proto = pad_random_max16(message_proto.SerializeToString())
    header, ct, mk = ratchet_encrypt(state, proto, ad)
    pkmsg = PreKeySignalMessage(
        registration_id=1234,
        one_time_pre_key_id=result.used_one_time_pre_key_id,
        signed_pre_key_id=result.used_signed_pre_key_id,
        base_key=result.ephemeral_public,
        identity_key=result.identity_public,
        message=SignalMessage(header=header, ciphertext=ct),
    )
    return pkmsg.encode(alice_ik.public, bob.identity_public, mk), alice_ik, state, ad


def _make_peer_msg(state: object, ad: bytes, text: str) -> bytes:
    from pywhats.messaging.padding import pad_random_max16

    proto = pad_random_max16(MessageProto(conversation=text).SerializeToString())
    header, ct, mk = ratchet_encrypt(state, proto, ad)  # type: ignore[arg-type]
    return SignalMessage(header=header, ciphertext=ct).encode(ad[:32], ad[32:], mk)


def _wrap_message(*, message_id: str, from_jid: JID, enc_type: str, ciphertext: bytes) -> bytes:
    enc = Node(tag="enc", attrs={"v": "2", "type": enc_type}, content=ciphertext)
    msg = Node(
        tag="message",
        attrs={
            "id": message_id,
            "from": from_jid,
            "type": "text",
            "t": "1700000000",
        },
        content=[enc],
    )
    return encode(msg)


def _wrap_participant_message(
    *, message_id: str, from_jid: JID, to_jid: JID, enc_type: str, ciphertext: bytes
) -> bytes:
    enc = Node(tag="enc", attrs={"v": "2", "type": enc_type}, content=ciphertext)
    msg = Node(
        tag="message",
        attrs={
            "id": message_id,
            "from": from_jid,
            "type": "text",
            "t": "1700000000",
        },
        content=[
            Node(
                tag="participants",
                content=[Node(tag="to", attrs={"jid": to_jid}, content=[enc])],
            )
        ],
    )
    return encode(msg)


def _build_receiver(
    *,
    transport: FakeTransport,
    bob: FakeResponderIdentity,
    retry_handler: FakeRetryHandler | None = None,
    lid_map: InMemoryLidMap | None = None,
    app_state_keys: object | None = None,
    history_sync_handler: object | None = None,
) -> tuple[
    Receiver,
    list[tuple[str, tuple[object, ...]]],
    AckRouter,
    PendingIqMap,
    InMemorySessionStore,
]:
    events: list[tuple[str, tuple[object, ...]]] = []

    async def emit(event: str, *args: object) -> None:
        events.append((event, args))

    router = AckRouter()
    iq_map = PendingIqMap()
    sessions = InMemorySessionStore()
    receiver = Receiver(
        transport=transport,
        router=router,
        iq_map=iq_map,
        session_store=sessions,
        identity=bob,
        emit=emit,
        own_jid=JID(user="15550000000", server="s.whatsapp.net"),
        retry_handler=retry_handler,
        lid_map=lid_map,
        app_state_keys=app_state_keys,
        history_sync_handler=history_sync_handler,  # type: ignore[arg-type]
    )
    return receiver, events, router, iq_map, sessions


# --- tests -----------------------------------------------------------


@pytest.mark.asyncio
async def test_history_sync_notification_from_self_triggers_handler() -> None:
    from pywhats.proto import Message as MessageProto
    from pywhats.proto import ProtocolMessage

    transport = FakeTransport()
    bob = _bob_side()
    called: list[object] = []

    async def _handler(notif: object) -> None:
        called.append(notif)

    receiver, _events, _, _, _ = _build_receiver(
        transport=transport, bob=bob, history_sync_handler=_handler
    )
    proto = MessageProto()
    pm = proto.protocol_message
    pm.type = ProtocolMessage.HISTORY_SYNC_NOTIFICATION
    pm.history_sync_notification.direct_path = "/hist/blob.enc"
    pm.history_sync_notification.media_key = b"\x01" * 32

    # Self-sent: sender user == own_jid user.
    own = JID(user="15550000000", server="s.whatsapp.net")
    handled = receiver._handle_protocol_message(proto, own)
    assert handled is True
    await asyncio.sleep(0)  # let the scheduled handler task run
    assert len(called) == 1
    assert called[0].direct_path == "/hist/blob.enc"


@pytest.mark.asyncio
async def test_history_sync_notification_from_other_is_ignored() -> None:
    from pywhats.proto import Message as MessageProto
    from pywhats.proto import ProtocolMessage

    transport = FakeTransport()
    bob = _bob_side()
    called: list[object] = []

    async def _handler(notif: object) -> None:
        called.append(notif)

    receiver, _events, _, _, _ = _build_receiver(
        transport=transport, bob=bob, history_sync_handler=_handler
    )
    proto = MessageProto()
    pm = proto.protocol_message
    pm.type = ProtocolMessage.HISTORY_SYNC_NOTIFICATION
    pm.history_sync_notification.direct_path = "/hist/blob.enc"

    other = JID(user="99999999999", server="s.whatsapp.net")
    handled = receiver._handle_protocol_message(proto, other)
    await asyncio.sleep(0)
    # Recognised (so the raw bytes aren't logged) but not acted on.
    assert handled is True
    assert called == []


@pytest.mark.asyncio
async def test_pkmsg_decrypts_and_emits_message_and_sends_delivery_receipt() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    peer_jid = JID(user="15551234567", server="s.whatsapp.net")
    ct, _alice_ik, _alice_state, _ad = _make_peer_pkmsg(bob, "hello from peer")
    frame = _wrap_message(
        message_id="AAAAAAAAAAAAAAAA", from_jid=peer_jid, enc_type="pkmsg", ciphertext=ct
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame)
    # let the receiver process
    for _ in range(50):
        if events and transport.outbound_frames:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Message event was emitted.
    msg_events = [e for e in events if e[0] == "message"]
    assert len(msg_events) == 1
    emitted = msg_events[0][1][0]
    assert isinstance(emitted, Message)
    assert emitted.text == "hello from peer"
    assert emitted.id == "AAAAAAAAAAAAAAAA"
    assert emitted.from_me is False
    assert emitted.sender.user == peer_jid.user

    # Delivery receipt was shipped.
    assert len(transport.outbound_frames) == 1
    receipt = decode(transport.outbound_frames[0])
    assert receipt.tag == "receipt"
    assert receipt.get_str("id") == "AAAAAAAAAAAAAAAA"
    assert receipt.get_str("type") == "delivery"


@pytest.mark.asyncio
async def test_wrapped_participant_pkmsg_selects_own_device() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    peer_jid = JID(user="15551234567", server="s.whatsapp.net", device=4)
    own_jid = JID(user="15550000000", server="s.whatsapp.net")
    ct, _alice_ik, _alice_state, _ad = _make_peer_pkmsg(bob, "wrapped")
    frame = _wrap_participant_message(
        message_id="BBBBBBBBBBBBBBBB",
        from_jid=peer_jid,
        to_jid=own_jid,
        enc_type="pkmsg",
        ciphertext=ct,
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame)
    for _ in range(50):
        if [e for e in events if e[0] == "message"]:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    msgs = [e for e in events if e[0] == "message"]
    assert len(msgs) == 1
    emitted = msgs[0][1][0]
    assert isinstance(emitted, Message)
    assert emitted.text == "wrapped"


@pytest.mark.asyncio
async def test_msg_decrypts_without_reinit_after_pkmsg() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    peer_jid = JID(user="15551234567", server="s.whatsapp.net")
    ct1, _alice_ik, alice_state, ad = _make_peer_pkmsg(bob, "first")
    ct2 = _make_peer_msg(alice_state, ad, "second")

    frame1 = _wrap_message(
        message_id="AAAAAAAAAAAAAAA1", from_jid=peer_jid, enc_type="pkmsg", ciphertext=ct1
    )
    frame2 = _wrap_message(
        message_id="AAAAAAAAAAAAAAA2", from_jid=peer_jid, enc_type="msg", ciphertext=ct2
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame1)
    await transport.inbound.put(frame2)
    for _ in range(100):
        msgs = [e for e in events if e[0] == "message"]
        if len(msgs) >= 2 and len(transport.outbound_frames) >= 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    msgs = [e for e in events if e[0] == "message"]
    assert len(msgs) == 2
    first = msgs[0][1][0]
    second = msgs[1][1][0]
    assert isinstance(first, Message)
    assert isinstance(second, Message)
    assert first.text == "first"
    assert second.text == "second"
    # One receipt per message.
    assert len(transport.outbound_frames) == 2


@pytest.mark.asyncio
async def test_lid_msg_migrates_known_pn_session_before_decrypt() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    lid_map = InMemoryLidMap()
    lid_map.set("15551234567", "111222333444555")
    receiver, events, _, _, sessions = _build_receiver(
        transport=transport,
        bob=bob,
        lid_map=lid_map,
    )

    peer_pn = JID(user="15551234567", server="s.whatsapp.net")
    peer_lid = JID(user="111222333444555", server="lid")
    ct1, _alice_ik, alice_state, ad = _make_peer_pkmsg(bob, "first")
    ct2 = _make_peer_msg(alice_state, ad, "lid second")
    frame1 = _wrap_message(
        message_id="CCCCCCCCCCCCCCC1", from_jid=peer_pn, enc_type="pkmsg", ciphertext=ct1
    )
    frame2 = _wrap_message(
        message_id="CCCCCCCCCCCCCCC2", from_jid=peer_lid, enc_type="msg", ciphertext=ct2
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame1)
    await transport.inbound.put(frame2)
    for _ in range(100):
        msgs = [e for e in events if e[0] == "message"]
        if len(msgs) >= 2 and len(transport.outbound_frames) >= 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    msgs = [e for e in events if e[0] == "message"]
    assert len(msgs) == 2
    second = msgs[1][1][0]
    assert isinstance(second, Message)
    assert second.text == "lid second"
    assert second.sender == peer_lid
    assert sessions.load(session_id(peer_pn)) is None
    assert sessions.load(session_id(peer_lid)) is not None


@pytest.mark.asyncio
async def test_retry_receipt_routes_embedded_prekey_bundle_and_acks() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    retry_handler = FakeRetryHandler(calls=[])
    receiver, _events, _, _, _ = _build_receiver(
        transport=transport,
        bob=bob,
        retry_handler=retry_handler,
    )
    peer_ik = IdentityKeyPair.generate()
    peer_spk = SignedPreKey.generate(peer_ik, key_id=44)
    peer_opk = generate_pre_key(key_id=55)
    receipt = Node(
        tag="receipt",
        attrs={
            "id": "MID-RETRY",
            "from": JID(user="15551234567", server="s.whatsapp.net", device=9),
            "participant": JID(user="15551234567", server="s.whatsapp.net", device=9),
            "type": "retry",
        },
        content=[
            Node(tag="retry", attrs={"count": "1", "v": "1", "t": "1700000000"}),
            Node(tag="registration", content=(1234).to_bytes(4, "big")),
            Node(
                tag="keys",
                content=[
                    Node(tag="identity", content=signal_pubkey(peer_ik.public)),
                    Node(
                        tag="skey",
                        content=[
                            Node(tag="id", content=peer_spk.key_id.to_bytes(3, "big")),
                            Node(tag="value", content=signal_pubkey(peer_spk.public)),
                            Node(tag="signature", content=peer_spk.signature),
                        ],
                    ),
                    Node(
                        tag="key",
                        content=[
                            Node(tag="id", content=peer_opk.key_id.to_bytes(3, "big")),
                            Node(tag="value", content=signal_pubkey(peer_opk.public)),
                        ],
                    ),
                ],
            ),
        ],
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(encode(receipt))
    for _ in range(50):
        if retry_handler.calls and transport.outbound_frames:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len(retry_handler.calls) == 1
    msg_id, peer, bundle, count = retry_handler.calls[0]
    assert msg_id == "MID-RETRY"
    assert peer.device == 9
    assert count == 1
    assert bundle is not None
    assert bundle.signed_pre_key_id == peer_spk.key_id
    ack = decode(transport.outbound_frames[0])
    assert ack.tag == "ack"
    assert ack.get_str("class") == "receipt"
    assert ack.get_str("type") == "retry"


@pytest.mark.asyncio
async def test_malformed_frame_does_not_crash_reader() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    peer_jid = JID(user="15559998888", server="s.whatsapp.net")
    ct, _, _, _ = _make_peer_pkmsg(bob, "after-garbage")
    good = _wrap_message(
        message_id="AAAAAAAAAAAAAAAA", from_jid=peer_jid, enc_type="pkmsg", ciphertext=ct
    )

    task = asyncio.create_task(receiver.run())
    # Garbage frame first; reader must not die.
    await transport.inbound.put(b"\x00this-is-not-a-valid-frame")
    await transport.inbound.put(good)
    for _ in range(50):
        if [e for e in events if e[0] == "message"]:
            break
        await asyncio.sleep(0.01)
    assert task.done() is False, "reader died on a bad frame"
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len([e for e in events if e[0] == "message"]) == 1


@pytest.mark.asyncio
async def test_decrypt_failure_emits_decrypt_error_event() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    peer_jid = JID(user="15557654321", server="s.whatsapp.net")
    # msg (not pkmsg) for a peer with no established session: decrypt must fail.
    bogus = SignalMessage(
        header=_bogus_header(),
        ciphertext=b"nonsense",
    ).encode(b"A" * 32, bob.identity_public, b"M" * 32)
    frame = _wrap_message(
        message_id="ABABABABABABABAB", from_jid=peer_jid, enc_type="msg", ciphertext=bogus
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame)
    for _ in range(50):
        if [e for e in events if e[0] == "decrypt_error"]:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    errs = [e for e in events if e[0] == "decrypt_error"]
    assert len(errs) == 1
    assert errs[0][1][0] == "ABABABABABABABAB"
    # No message event fired. Receiver now sends a retry receipt back
    # asking the peer to re-init the session — that's the only
    # outbound frame.
    assert [e for e in events if e[0] == "message"] == []
    assert len(transport.outbound_frames) == 1
    retry = decode(transport.outbound_frames[0])
    assert retry.tag == "receipt"
    assert retry.get_str("type") == "retry"
    assert retry.get_str("id") == "ABABABABABABABAB"
    assert retry.get_child("retry") is not None


def _bogus_header() -> MessageHeader:
    return MessageHeader(dh=b"\x00" * 32, pn=0, n=0)


@pytest.mark.asyncio
async def test_ack_dispatches_to_router() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, _events, router, _iq, _ = _build_receiver(transport=transport, bob=bob)

    # Register a pending send, then feed a matching <ack>.
    fut = router.register("MID-0001")

    ack = encode(Node(tag="ack", attrs={"id": "MID-0001", "class": "message"}))

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(ack)

    result = await asyncio.wait_for(fut, timeout=1.0)
    assert result is None  # plain ack, no retry

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_iq_response_resolves_pending_future() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, _events, _router, iq_map, _ = _build_receiver(transport=transport, bob=bob)

    fut = iq_map.register("IQ-0042")
    iq = encode(Node(tag="iq", attrs={"id": "IQ-0042", "type": "result"}))

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(iq)

    node = await asyncio.wait_for(fut, timeout=1.0)
    assert node.tag == "iq"
    assert node.get_str("id") == "IQ-0042"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_receipt_and_presence_surface_as_events_not_crashed() -> None:
    # Since #38 the receiver surfaces read receipts and peer presence as
    # `receipt` / `presence` events (whatsmeow handleReceipt/handlePresence)
    # rather than silently dropping them; it must still never crash on them.
    transport = FakeTransport()
    bob = _bob_side()
    receiver, events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(encode(Node(tag="receipt", attrs={"id": "X", "type": "read"})))
    await transport.inbound.put(
        encode(Node(tag="presence", attrs={"from": "1@s.whatsapp.net", "type": "unavailable"}))
    )
    # Yield to let the receiver drain the queue.
    await asyncio.sleep(0.05)
    assert not task.done()
    emitted = {name for name, _ in events}
    assert "receipt" in emitted
    assert "presence" in emitted
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_reader_cancels_cleanly_on_disconnect() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, _events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    task = asyncio.create_task(receiver.run())
    # Give it a tick to actually enter the loop.
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_reader_stops_when_transport_closes() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, _events, _, _, _ = _build_receiver(transport=transport, bob=bob)

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(ConnectionClosed("bye"))
    await asyncio.wait_for(task, timeout=1.0)


@pytest.mark.asyncio
async def test_ack_with_retry_child_resolves_as_retry() -> None:
    transport = FakeTransport()
    bob = _bob_side()
    receiver, _events, router, _, _ = _build_receiver(transport=transport, bob=bob)

    fut = router.register("MID-RETRY")
    ack = encode(
        Node(
            tag="ack",
            attrs={"id": "MID-RETRY", "class": "message"},
            content=[Node(tag="retry", attrs={"count": "1"})],
        )
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(ack)

    result = await asyncio.wait_for(fut, timeout=1.0)
    assert result is not None
    assert result.attrs.get("count") == "1"
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_pkmsg_saves_roll_back_together_when_identity_save_fails(tmp_path) -> None:
    """A crash between the session and identity writes persists neither.

    The receiver saves the ratchet session and the peer identity in two
    store calls; with ``atomic=SqliteStore.transaction`` a failure in the
    second write must roll the first back, so no session exists without
    its pinned identity.
    """
    from pywhats.signal.experimental.sqlite_store import SqliteStore

    transport = FakeTransport()
    bob = _bob_side()
    store = SqliteStore(tmp_path / "state.db")

    class _FailingIdentityStore:
        def load(self, sid: str) -> bytes | None:
            return store.identities.load(sid)

        def save(self, sid: str, identity_public: bytes) -> None:
            raise RuntimeError("simulated crash between writes")

        def delete(self, sid: str) -> None:
            store.identities.delete(sid)

    events: list[tuple[str, tuple[object, ...]]] = []

    async def emit(event: str, *args: object) -> None:
        events.append((event, args))

    receiver = Receiver(
        transport=transport,
        router=AckRouter(),
        iq_map=PendingIqMap(),
        session_store=store.sessions,
        identity=bob,
        emit=emit,
        own_jid=JID(user="15550000000", server="s.whatsapp.net"),
        identity_store=_FailingIdentityStore(),
        atomic=store.transaction,
    )

    peer_jid = JID(user="15551234567", server="s.whatsapp.net")
    ct, _alice_ik, _alice_state, _ad = _make_peer_pkmsg(bob, "boom")
    frame = _wrap_message(
        message_id="EEEEEEEEEEEEEEE1", from_jid=peer_jid, enc_type="pkmsg", ciphertext=ct
    )

    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame)
    for _ in range(50):
        if events:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert any(e[0] == "decrypt_error" for e in events)
    # The session write was rolled back along with the failed identity write.
    assert store.sessions.load(session_id(peer_jid)) is None
    store.close()


# --- app-state sync key share (issue #35a) ----------------------------


def _key_share_proto(keys: list[tuple[bytes, bytes, int]]) -> MessageProto:
    """Build a ``protocol_message`` APP_STATE_SYNC_KEY_SHARE Message proto."""
    from pywhats.proto import ProtocolMessage

    proto = MessageProto()
    pm = proto.protocol_message
    pm.type = ProtocolMessage.APP_STATE_SYNC_KEY_SHARE
    for key_id, key_data, timestamp in keys:
        key = pm.app_state_sync_key_share.keys.add()
        key.key_id.key_id = key_id
        key.key_data.key_data = key_data
        key.key_data.timestamp = timestamp
        key.key_data.fingerprint.raw_id = 7
        key.key_data.fingerprint.current_index = 1
        key.key_data.fingerprint.device_indexes.append(0)
    return proto


async def _run_one_message(receiver: Receiver, transport: FakeTransport, frame: bytes) -> None:
    task = asyncio.create_task(receiver.run())
    await transport.inbound.put(frame)
    for _ in range(50):
        if transport.outbound_frames:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_app_state_key_share_from_own_primary_is_persisted() -> None:
    from pywhats.appstate import InMemoryAppStateKeyStore
    from pywhats.proto.e2e_pb2 import AppStateSyncKeyFingerprint

    transport = FakeTransport()
    bob = _bob_side()
    app_keys = InMemoryAppStateKeyStore()
    receiver, events, _, _, _ = _build_receiver(
        transport=transport, bob=bob, app_state_keys=app_keys
    )

    # Same user as own_jid — the key share arrives self-sent from our
    # own primary (device 0), as observed in the live capture.
    own_primary = JID(user="15550000000", server="s.whatsapp.net")
    proto = _key_share_proto([(b"\x00\x00\x01", b"A" * 32, 100), (b"\x00\x00\x02", b"B" * 32, 200)])
    ct, _, _, _ = _make_peer_pkmsg_proto(bob, proto)
    frame = _wrap_message(
        message_id="KEYSHARE00000001", from_jid=own_primary, enc_type="pkmsg", ciphertext=ct
    )
    await _run_one_message(receiver, transport, frame)

    got1 = app_keys.get(b"\x00\x00\x01")
    got2 = app_keys.get(b"\x00\x00\x02")
    assert got1 is not None
    assert got1.key_data == b"A" * 32
    assert got1.timestamp == 100
    assert got2 is not None
    assert got2.key_data == b"B" * 32
    # The fingerprint is stored as the serialized proto (whatsmeow
    # handleAppStateSyncKeyShare marshals it before PutAppStateSyncKey).
    fp = AppStateSyncKeyFingerprint()
    fp.ParseFromString(got1.fingerprint)
    assert fp.raw_id == 7
    assert fp.current_index == 1

    # The message is still processed normally: event emitted, receipt sent.
    assert [e for e in events if e[0] == "message"]
    assert transport.outbound_frames
    receipt = decode(transport.outbound_frames[0])
    assert receipt.tag == "receipt"


@pytest.mark.asyncio
async def test_app_state_key_share_from_other_peer_is_ignored() -> None:
    from pywhats.appstate import InMemoryAppStateKeyStore

    transport = FakeTransport()
    bob = _bob_side()
    app_keys = InMemoryAppStateKeyStore()
    receiver, events, _, _, _ = _build_receiver(
        transport=transport, bob=bob, app_state_keys=app_keys
    )

    # A key share must only be accepted from ourselves (whatsmeow
    # handleProtocolMessage returns early unless info.IsFromMe).
    other_peer = JID(user="15551234567", server="s.whatsapp.net")
    proto = _key_share_proto([(b"\x00\x00\x01", b"A" * 32, 100)])
    ct, _, _, _ = _make_peer_pkmsg_proto(bob, proto)
    frame = _wrap_message(
        message_id="KEYSHARE00000002", from_jid=other_peer, enc_type="pkmsg", ciphertext=ct
    )
    await _run_one_message(receiver, transport, frame)

    assert app_keys.get(b"\x00\x00\x01") is None
    # Still processed as a normal (empty-text) message.
    assert [e for e in events if e[0] == "message"]


@pytest.mark.asyncio
async def test_app_state_key_share_key_material_is_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from pywhats.appstate import InMemoryAppStateKeyStore

    transport = FakeTransport()
    bob = _bob_side()
    app_keys = InMemoryAppStateKeyStore()
    receiver, _events, _, _, _ = _build_receiver(
        transport=transport, bob=bob, app_state_keys=app_keys
    )

    own_primary = JID(user="15550000000", server="s.whatsapp.net")
    key_data = b"\xaa\xbb\xcc\xdd" * 8
    proto = _key_share_proto([(b"\x00\x00\x01", key_data, 100)])
    ct, _, _, _ = _make_peer_pkmsg_proto(bob, proto)
    frame = _wrap_message(
        message_id="KEYSHARE00000003", from_jid=own_primary, enc_type="pkmsg", ciphertext=ct
    )
    import logging

    with caplog.at_level(logging.DEBUG, logger="pywhats"):
        await _run_one_message(receiver, transport, frame)

    # A handled protocol message must not fall through to the
    # empty-text hex dump — that would write key material to the log.
    assert app_keys.get(b"\x00\x00\x01") is not None
    assert key_data.hex() not in caplog.text


@pytest.mark.asyncio
async def test_app_state_key_writes_roll_back_together(tmp_path) -> None:
    """A failure on the Nth key rolls back the keys stored before it.

    The 43-key live share must land all-or-nothing (SqliteStore.transaction),
    and a key-store failure must not abort normal message processing —
    whatsmeow isolates handleAppStateSyncKeyShare from the message path.
    """
    from pywhats.appstate import AppStateSyncKey
    from pywhats.signal.experimental.sqlite_store import SqliteStore

    transport = FakeTransport()
    bob = _bob_side()
    store = SqliteStore(tmp_path / "state.db")

    class _FailingSecondPut:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, key_id: bytes) -> AppStateSyncKey | None:
            return store.app_state_keys.get(key_id)

        def put(self, key: AppStateSyncKey) -> None:
            self.calls += 1
            if self.calls >= 2:
                raise RuntimeError("simulated crash between key writes")
            store.app_state_keys.put(key)

    events: list[tuple[str, tuple[object, ...]]] = []

    async def emit(event: str, *args: object) -> None:
        events.append((event, args))

    receiver = Receiver(
        transport=transport,
        router=AckRouter(),
        iq_map=PendingIqMap(),
        session_store=store.sessions,
        identity=bob,
        emit=emit,
        own_jid=JID(user="15550000000", server="s.whatsapp.net"),
        app_state_keys=_FailingSecondPut(),
        atomic=store.transaction,
    )

    own_primary = JID(user="15550000000", server="s.whatsapp.net")
    proto = _key_share_proto([(b"\x00\x00\x01", b"A" * 32, 100), (b"\x00\x00\x02", b"B" * 32, 200)])
    ct, _, _, _ = _make_peer_pkmsg_proto(bob, proto)
    frame = _wrap_message(
        message_id="KEYSHARE00000004", from_jid=own_primary, enc_type="pkmsg", ciphertext=ct
    )
    await _run_one_message(receiver, transport, frame)

    # The first key's write rolled back with the second's failure.
    assert store.app_state_keys.get(b"\x00\x00\x01") is None
    # The message event and receipt still went out.
    assert [e for e in events if e[0] == "message"]
    assert transport.outbound_frames
    store.close()
