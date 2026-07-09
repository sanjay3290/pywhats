# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Outbound text-message send flow.

The :class:`Sender` orchestrates the seven steps laid out in issue #9:

    1. Generate a fresh message id.
    2. Serialise a ``Message { conversation: text }`` protobuf.
    3. Ensure a Signal session exists for the peer; if not, fetch a
       prekey bundle via an ``iq get`` / ``usync`` stanza and run X3DH.
    4. Signal-encrypt the protobuf bytes to a ``SignalMessage`` or
       ``PreKeySignalMessage`` frame.
    5. Wrap the ciphertext in an XMPP-style ``<message ...><enc ...>``
       binary stanza.
    6. Ship it over the Noise transport.
    7. Await a matching ``<ack>`` stanza via the router, with a
       configurable timeout and one automatic retry when the server
       responds with ``<retry>``.

The sender is deliberately decoupled from the frame-reader task (issue
#10): every read-side hook goes through :class:`AckRouterProtocol` so
the tests can drive acks and retries synchronously from a fake.

Prose references consulted (no reference-implementation source read):

* Public WhatsApp multi-device protocol writeups describing the
  ``<message id to type><enc v type>ciphertext</enc></message>`` stanza
  shape, the two ``enc.type`` values (``pkmsg`` for the first message
  in a new session, ``msg`` for subsequent messages), and the
  ``iq get`` / ``usync`` shape used to fetch prekey bundles.
* The Signal X3DH and Double Ratchet specifications
  (https://signal.org/docs/) for the per-peer session lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

from pywhats.binary import Node, encode
from pywhats.binary.node import AttrValue
from pywhats.events import JID, Message
from pywhats.proto import Message as MessageProto
from pywhats.signal.experimental import (
    IdentityKeyPair,
    IdentityStore,
    InMemoryIdentityStore,
    InMemoryLidMap,
    LidMap,
    PreKeyBundle,
    RatchetState,
    SessionStore,
    SignalMessage,
    ratchet_encrypt,
    ratchet_init_alice,
    x3dh_initiator,
)
from pywhats.signal.experimental.types import PreKeySignalMessage

from .addressing import migrate_pn_session_to_lid, session_id
from .ids import new_message_id
from .padding import pad_random_max16
from .router import AckRouterProtocol, RetrySignal
from .usync import UserSyncEntry

_log = logging.getLogger("pywhats.messaging")


# --- small interface types the sender depends on --------------------


class NoiseTransportProtocol(Protocol):
    """The subset of :class:`pywhats.socket.noise.NoiseTransport` we use."""

    async def send(self, plaintext: bytes) -> None: ...


class IdentityProvider(Protocol):
    """The sender's own long-term Signal identity + registration id.

    Supplied by :class:`pywhats.store.DeviceStore` in production; a
    plain dataclass in tests.
    """

    @property
    def identity_private(self) -> bytes: ...

    @property
    def identity_public(self) -> bytes: ...

    @property
    def registration_id(self) -> int: ...


# Callable signature for fetching a prekey bundle. The sender does not
# build the iq/usync stanza itself - that's a separate concern handed
# in at construction. Production wiring belongs in a future issue; for
# now :meth:`Sender.build_usync_node` gives callers a ready-made stanza
# they can ship and the fetcher just needs to return the parsed bundle.
PrekeyFetcher = Callable[[JID], Awaitable[PreKeyBundle]]
DeviceFetcher = Callable[[Iterable[JID]], Awaitable[dict[JID, UserSyncEntry]]]


# --- config ---------------------------------------------------------


@dataclass(frozen=True)
class SenderConfig:
    """Tunables for the send flow."""

    ack_timeout_seconds: float = 30.0
    # The wire tag on the outer stanza. The server accepts ``text`` for
    # plain conversation messages; this is configurable so callers can
    # experiment without patching the library.
    message_type: str = "text"
    # The ``v`` attribute on the ``<enc>`` child. ``2`` is the Signal v2
    # framing used by the multi-device protocol.
    enc_version: str = "2"


# --- session records ------------------------------------------------


@dataclass
class _PeerSessionMeta:
    """Per-peer metadata we stash alongside the ratchet state.

    The X3DH inputs have to ride on the *first* outbound message as a
    ``PreKeySignalMessage`` so the responder can rebuild the same
    shared secret; after that, plain ``SignalMessage`` frames suffice.
    """

    # Peer's long-term Signal identity public key. Needed as part of
    # the X3DH associated data on every ratchet encrypt.
    peer_identity: bytes = b""

    # X3DH initiator outputs. Only populated until the first send has
    # been ACK'd; after that we drop them and emit plain SignalMessages.
    pending_prekey: _PendingPreKey | None = None


@dataclass
class _PendingPreKey:
    registration_id: int
    one_time_pre_key_id: int | None
    signed_pre_key_id: int
    base_key: bytes
    identity_key: bytes


@dataclass
class _SentMessage:
    chat: JID
    text: str
    plaintext: bytes
    # The DSM-wrapped variant shipped to our OWN other devices (see
    # _build_dsm_plaintext). Kept alongside `plaintext` so a retry
    # receipt from one of our own devices re-encrypts the wrapper, not
    # the bare body.
    own_plaintext: bytes = b""
    retry_count: int = 0
    # The stanza `type` attribute the original send used ("text",
    # "reaction", ...), so a retry resend keeps the same routing hint.
    message_type: str = "text"
    # The stanza `edit` attribute for edits/revokes, replayed on retry.
    edit: str | None = None


# --- sender ---------------------------------------------------------


class Sender:
    """Send-side orchestrator. See module docstring for the flow."""

    def __init__(
        self,
        *,
        transport: NoiseTransportProtocol,
        router: AckRouterProtocol,
        session_store: SessionStore,
        identity: IdentityProvider,
        prekey_fetcher: PrekeyFetcher,
        own_jid: JID,
        device_fetcher: DeviceFetcher | None = None,
        adv_signed_device_identity: bytes | None = None,
        identity_store: IdentityStore | None = None,
        lid_map: LidMap | None = None,
        config: SenderConfig | None = None,
        sender_key_store: object | None = None,
    ) -> None:
        self._transport = transport
        self._router = router
        self._sessions = session_store
        self._identity = identity
        self._fetch_prekeys = prekey_fetcher
        self._fetch_devices = device_fetcher or _single_device_fetcher
        self._own_jid = own_jid
        self._adv_signed_device_identity = adv_signed_device_identity
        self._identity_store: IdentityStore = identity_store or InMemoryIdentityStore()
        self._lid_map: LidMap = lid_map or InMemoryLidMap()
        self._config = config or SenderConfig()
        self._sender_key_store = sender_key_store
        # Per-peer pending-prekey metadata is volatile state - we keep
        # it in memory only. If the process restarts before the first
        # message is ACK'd, the next send re-fetches the bundle.
        self._peer_meta: dict[str, _PeerSessionMeta] = {}
        self._sent: dict[str, _SentMessage] = {}

    # --- public API ----------------------------------------------

    async def send_text(self, chat: JID, text: str, *, reply_to: object | None = None) -> Message:
        """Encrypt, send, and await the server ack for a single text message.

        Raises :class:`TimeoutError` if no ack arrives within
        ``config.ack_timeout_seconds``. Retries exactly once when the
        server returns a ``<retry>`` stanza by discarding the peer
        session, fetching a fresh prekey bundle, and rebuilding the
        ciphertext under a new session.

        ``reply_to`` quotes an earlier message: pass the inbound
        :class:`pywhats.events.Message` (or a :class:`MessageKey` proto)
        being replied to and the body is wrapped in an
        ExtendedTextMessage carrying its ContextInfo.
        """
        if reply_to is not None:
            proto = self._build_reply_proto(text, reply_to)
        else:
            proto = MessageProto(conversation=text)
        return await self.send_message(chat, proto, text=text)

    @staticmethod
    def _build_reply_proto(text: str, reply_to: object) -> MessageProto:
        """Build an ExtendedTextMessage quoting ``reply_to`` (whatsmeow BuildReply).

        Accepts either an :class:`pywhats.events.Message` (what handlers
        receive — has a ``sender`` JID and body ``text``) or a
        ``MessageKey`` proto (author on ``.participant``).
        """
        proto = MessageProto()
        etm = proto.extended_text_message
        etm.text = text
        ci = etm.context_info
        sender = getattr(reply_to, "sender", None)
        if sender is not None:
            # events.Message: id + sender JID + the quoted body text.
            ci.stanza_id = reply_to.id  # type: ignore[attr-defined]
            ci.participant = f"{sender.user}@{sender.server}"
            quoted_text = getattr(reply_to, "text", "") or ""
            if quoted_text:
                ci.quoted_message.conversation = quoted_text
        else:
            # MessageKey proto: id on .id, author on .participant.
            ci.stanza_id = getattr(reply_to, "id", "") or ""
            participant = getattr(reply_to, "participant", "") or ""
            if participant:
                ci.participant = participant
        return proto

    async def send_message(
        self,
        chat: JID,
        message_proto: MessageProto,
        *,
        text: str = "",
        message_type: str | None = None,
        edit: str | None = None,
    ) -> Message:
        """Encrypt and send an arbitrary ``Message`` proto (e.g. an image).

        Serialises + WA-pads the proto and runs the same encrypt / send /
        ack / single-retry path as :meth:`send_text`. ``text`` is only the
        value surfaced on the returned :class:`Message` event.
        ``message_type`` overrides the stanza ``type`` attribute (e.g.
        ``"reaction"``, whatsmeow ``getTypeFromMessage``). ``edit`` sets
        the outer stanza ``edit`` attribute for edits/revokes (whatsmeow
        ``EditAttribute``).
        """
        message_id = new_message_id()
        plaintext = pad_random_max16(message_proto.SerializeToString())
        own_plaintext = self._build_dsm_plaintext(chat, message_proto)
        resolved_type = message_type or self._config.message_type
        _log.info("sender: preparing message id=%s to=%s", message_id, _fmt_jid(chat))

        message = await self._send_once(
            chat=chat,
            text=text,
            message_id=message_id,
            plaintext=plaintext,
            own_plaintext=own_plaintext,
            allow_retry=True,
            message_type=resolved_type,
            edit=edit,
        )
        self._sent[message.id] = _SentMessage(
            chat=chat,
            text=text,
            plaintext=plaintext,
            own_plaintext=own_plaintext,
            message_type=resolved_type,
            edit=edit,
        )
        return message

    def _build_dsm_plaintext(self, chat: JID, message_proto: MessageProto) -> bytes:
        """WA-pad the ``DeviceSentMessage`` wrapper for our own devices.

        When a companion sends, the copy fanned out to the account's own
        other devices must be ``Message { device_sent_message {
        destination_jid, message } }`` — that wrapper is what tells them
        "I sent this to <peer>" so they render it as outgoing. An
        unwrapped copy is silently dropped.
        """
        dsm = MessageProto()
        dsm.device_sent_message.destination_jid = str(_base_jid(chat))
        dsm.device_sent_message.message.CopyFrom(message_proto)
        return pad_random_max16(dsm.SerializeToString())

    async def send_group_text(self, group: JID, text: str, participants: list[JID]) -> Message:
        """Send a text message to a group via sender-key fan-out (#39).

        Distributes our SenderKeyDistributionMessage to every participant
        device over the existing 1:1 Signal sessions, then encrypts the
        content once as a group ``skmsg`` (whatsmeow ``sendGroup``). The
        SKDM ride-along is sent on every message here (whatsmeow only
        sends it when needed) — correct, just slightly heavier.
        """
        from pywhats.signal.experimental.sender_key import (
            build_distribution_message,
            create_sender_key_state,
            group_encrypt,
        )

        if self._sender_key_store is None:
            raise RuntimeError("group send requires a sender-key store")

        message_id = new_message_id()
        sender_addr = session_id(self._own_jid)
        state = self._sender_key_store.load(str(group), sender_addr)  # type: ignore[attr-defined]
        if state is None:
            key_id = getattr(self._identity, "registration_id", 0) or 1
            state = create_sender_key_state(key_id=key_id)

        skd = MessageProto()
        skd.sender_key_distribution_message.group_id = str(group)
        skd.sender_key_distribution_message.axolotl_sender_key_distribution_message = (
            build_distribution_message(state)
        )
        skd_plaintext = pad_random_max16(skd.SerializeToString())

        content = pad_random_max16(MessageProto(conversation=text).SerializeToString())
        skmsg, new_state = group_encrypt(state, content)
        self._sender_key_store.save(str(group), sender_addr, new_state)  # type: ignore[attr-defined]

        # Resolve every participant's devices (usync). Unlike 1:1 send we
        # do not add our own devices here — the SKDM fans out to the group
        # members. Our own other devices learn the sender key through their
        # own copy of app state / history, matching a companion device.
        device_map = await self._fetch_devices([_base_jid(p) for p in participants])
        devices: list[JID] = []
        for participant in participants:
            base = _base_jid(participant)
            entry = device_map.get(base)
            if entry is None:
                devices.append(base)
            else:
                devices.extend(entry.devices)

        participant_nodes: list[Node] = []
        for device in _dedupe_devices(devices):
            if _same_full_jid(device, self._own_jid):
                continue
            enc_type, ciphertext = await self._encrypt_for_peer(device, skd_plaintext)
            wire = await self._resolve_signal_address(device)
            participant_nodes.append(self._build_participant_node(wire, enc_type, ciphertext))

        stanza = self._build_group_message_node(message_id, group, participant_nodes, skmsg)
        fut = self._router.register(message_id)
        try:
            await self._transport.send(encode(stanza))
            await asyncio.wait_for(fut, timeout=self._config.ack_timeout_seconds)
        finally:
            self._router.cancel(message_id)

        return Message(
            id=message_id,
            chat=group,
            sender=self._own_jid,
            text=text,
            timestamp=int(time.time()),
            from_me=True,
        )

    def _build_group_message_node(
        self, message_id: str, group: JID, participant_nodes: list[Node], skmsg: bytes
    ) -> Node:
        content: list[Node] = [Node(tag="participants", content=participant_nodes)]
        if self._adv_signed_device_identity:
            content.append(Node(tag="device-identity", content=self._adv_signed_device_identity))
        content.append(
            Node(tag="enc", attrs={"v": self._config.enc_version, "type": "skmsg"}, content=skmsg)
        )
        return Node(
            tag="message",
            attrs={"id": message_id, "to": group, "type": "text"},
            content=content,
        )

    async def handle_retry_receipt(
        self,
        message_id: str,
        peer: JID,
        bundle: PreKeyBundle | None = None,
        count: int = 1,
    ) -> None:
        cached = self._sent.get(message_id)
        if cached is None:
            _log.info("sender: retry receipt for uncached id=%s peer=%s", message_id, peer)
            return
        if cached.retry_count >= 2 or count > 2:
            _log.warning(
                "sender: retry cap reached id=%s peer=%s count=%s",
                message_id,
                peer,
                count,
            )
            return

        cached.retry_count += 1
        self._drop_peer_session(peer)
        if bundle is not None:
            state, meta = self._establish_session_from_bundle(bundle)
            signal_peer = await self._resolve_signal_address(peer)
            sid = session_id(signal_peer)
            self._sessions.save(sid, state)
            self._peer_meta[sid] = meta

        # A retry from one of our own devices must re-encrypt the
        # DSM-wrapped copy, not the bare body.
        retry_plaintext = cached.plaintext
        if cached.own_plaintext and _base_jid(peer) == _base_jid(self._own_jid):
            retry_plaintext = cached.own_plaintext
        enc_type, ciphertext = await self._encrypt_for_peer(peer, retry_plaintext)
        stanza = self._build_message_node(
            message_id=message_id,
            to=_base_jid(cached.chat),
            participants=[self._build_participant_node(peer, enc_type, ciphertext, count=count)],
            message_type=cached.message_type,
            edit=cached.edit,
        )
        fut = self._router.register(message_id)
        try:
            await self._transport.send(encode(stanza))
            result = await asyncio.wait_for(fut, timeout=self._config.ack_timeout_seconds)
        except TimeoutError:
            self._router.cancel(message_id)
            _log.warning("sender: retry resend ack timeout id=%s peer=%s", message_id, peer)
            return
        finally:
            self._router.cancel(message_id)
        if isinstance(result, RetrySignal):
            _log.info("sender: retry resend got retry id=%s attrs=%s", message_id, result.attrs)
            return
        retry_meta = self._peer_meta.get(session_id(await self._resolve_signal_address(peer)))
        if retry_meta is not None:
            retry_meta.pending_prekey = None

    # --- internals -----------------------------------------------

    async def _send_once(
        self,
        *,
        chat: JID,
        text: str,
        message_id: str,
        plaintext: bytes,
        own_plaintext: bytes,
        allow_retry: bool,
        message_type: str | None = None,
        edit: str | None = None,
    ) -> Message:
        target_devices = await self._target_devices(chat)
        participant_nodes: list[Node] = []
        encrypted_devices: list[JID] = []
        own_base = _base_jid(self._own_jid)
        for device in target_devices:
            # Our own other devices get the DSM-wrapped copy; the peer's
            # devices get the bare body (see _build_dsm_plaintext).
            device_plaintext = own_plaintext if _base_jid(device) == own_base else plaintext
            enc_type, ciphertext = await self._encrypt_for_peer(device, device_plaintext)
            # The participant <to jid="..."> MUST match the JID we
            # encrypted under, not the user-facing PN. If we resolve
            # PN -> LID for the Signal session but ship the
            # ciphertext under <to jid=PN>, the recipient device
            # looks up its session by PN, finds no match for what we
            # encrypted, and silently drops — server still ACKs the
            # outer stanza, but the message never displays.
            wire_device = await self._resolve_signal_address(device)
            participant_nodes.append(
                self._build_participant_node(wire_device, enc_type, ciphertext)
            )
            encrypted_devices.append(device)

        stanza = self._build_message_node(
            message_id=message_id,
            to=_base_jid(chat),
            participants=participant_nodes,
            message_type=message_type,
            edit=edit,
        )
        frame = encode(stanza)

        fut = self._router.register(message_id)
        try:
            await self._transport.send(frame)
            _log.info("sender: sent id=%s", message_id)
            try:
                result = await asyncio.wait_for(fut, timeout=self._config.ack_timeout_seconds)
            except TimeoutError:
                self._router.cancel(message_id)
                _log.warning("sender: ack timeout id=%s", message_id)
                raise
        except BaseException:
            # Make sure we don't leak a pending future on any failure path.
            self._router.cancel(message_id)
            raise

        if isinstance(result, RetrySignal):
            if not allow_retry:
                raise RuntimeError(f"second retry requested for id={message_id}")
            _log.info("sender: server requested retry id=%s, refreshing session", message_id)
            retry_peer = self._retry_peer_from_signal(result, encrypted_devices)
            self._drop_peer_session(retry_peer)
            return await self._send_once(
                chat=chat,
                text=text,
                message_id=message_id,
                plaintext=plaintext,
                own_plaintext=own_plaintext,
                allow_retry=False,
                message_type=message_type,
                edit=edit,
            )

        _log.info("sender: ack id=%s", message_id)
        # On a successful send, discard any pending-prekey metadata so
        # the next outbound message uses a plain SignalMessage.
        for peer in encrypted_devices:
            resolved_peer = await self._resolve_signal_address(peer)
            meta = self._peer_meta.get(session_id(resolved_peer))
            if meta is not None:
                meta.pending_prekey = None

        return Message(
            id=message_id,
            chat=chat,
            sender=self._own_jid,
            text=text,
            timestamp=int(time.time()),
            from_me=True,
        )

    async def _encrypt_for_peer(self, peer: JID, plaintext: bytes) -> tuple[str, bytes]:
        """Return ``(enc_type, ciphertext)`` for the peer, running X3DH if needed.

        ``enc_type`` is ``"pkmsg"`` when the ciphertext is wrapped in a
        :class:`PreKeySignalMessage` (i.e. this is the first message of
        a new session), ``"msg"`` otherwise.
        """
        signal_peer = await self._resolve_signal_address(peer)
        sid = session_id(signal_peer)
        state = self._sessions.load(sid)
        meta = self._peer_meta.get(sid)

        if state is not None and meta is None:
            # Process restart: ratchet state survived on disk but the
            # in-memory pending-prekey + peer_identity went away. The
            # peer_identity is the only field we need to keep ratcheting
            # — the pending-prekey has already been delivered to the
            # peer (state is on disk, so at least one outbound went out
            # under this session).
            cached = self._identity_store.load(sid)
            if cached is not None:
                meta = _PeerSessionMeta(peer_identity=cached, pending_prekey=None)
                self._peer_meta[sid] = meta

        if state is None or meta is None:
            state, meta = await self._establish_session(signal_peer)
            self._peer_meta[sid] = meta
            self._identity_store.save(sid, meta.peer_identity)

        # X3DH 3.3: AD = Encode(IKA) || Encode(IKB). Feeding this as
        # the ratchet associated data keeps initiator and responder in
        # lockstep on every message.
        ad = self._identity.identity_public + meta.peer_identity

        header, ciphertext, mac_key = ratchet_encrypt(state, plaintext, ad)
        self._sessions.save(sid, state)

        signal = SignalMessage(header=header, ciphertext=ciphertext)
        inner = signal.encode(self._identity.identity_public, meta.peer_identity, mac_key)

        if meta is not None and meta.pending_prekey is not None:
            pp = meta.pending_prekey
            pkmsg = PreKeySignalMessage(
                registration_id=pp.registration_id,
                one_time_pre_key_id=pp.one_time_pre_key_id,
                signed_pre_key_id=pp.signed_pre_key_id,
                base_key=pp.base_key,
                identity_key=pp.identity_key,
                message=signal,
            )
            return "pkmsg", pkmsg.encode(
                self._identity.identity_public,
                meta.peer_identity,
                mac_key,
            )

        return "msg", inner

    async def _establish_session(self, peer: JID) -> tuple[RatchetState, _PeerSessionMeta]:
        bundle = await self._fetch_prekeys(peer)
        return self._establish_session_from_bundle(bundle)

    def _establish_session_from_bundle(
        self, bundle: PreKeyBundle
    ) -> tuple[RatchetState, _PeerSessionMeta]:
        identity = IdentityKeyPair(
            private=self._identity.identity_private,
            public=self._identity.identity_public,
        )
        result = x3dh_initiator(identity, bundle)
        state = ratchet_init_alice(result.shared_secret, bundle.signed_pre_key_public)
        meta = _PeerSessionMeta(
            peer_identity=bundle.identity_key,
            pending_prekey=_PendingPreKey(
                registration_id=self._identity.registration_id,
                one_time_pre_key_id=result.used_one_time_pre_key_id,
                signed_pre_key_id=result.used_signed_pre_key_id,
                base_key=result.ephemeral_public,
                identity_key=result.identity_public,
            ),
        )
        return state, meta

    def _drop_peer_session(self, peer: JID) -> None:
        peers = [peer]
        if peer.server == "lid":
            pn_user = self._lid_map.get_pn(peer.user)
            if pn_user is not None:
                peers.append(JID(user=pn_user, server="s.whatsapp.net", device=peer.device))
        else:
            lid_user = self._lid_map.get_lid(peer.user)
            if lid_user is not None:
                peers.append(JID(user=lid_user, server="lid", device=peer.device))
        for candidate in peers:
            sid = session_id(candidate)
            self._sessions.delete(sid)
            self._peer_meta.pop(sid, None)
            self._identity_store.delete(sid)

    async def _target_devices(self, chat: JID) -> list[JID]:
        if chat.device:
            return [chat]
        device_map = await self._fetch_devices([_base_jid(chat), _base_jid(self._own_jid)])
        devices: list[JID] = []
        for base in (_base_jid(chat), _base_jid(self._own_jid)):
            entry = device_map.get(base)
            if entry is None:
                devices.append(base)
                continue
            # Don't run _remember_lid_mapping here: it migrates the PN
            # session to a LID key right before encrypt, which deletes
            # the live PN session we're about to use. Outbound is on
            # PN end-to-end (see _resolve_signal_address); the LID
            # mapping is only useful once we re-enable LID-keyed
            # outbound. Receiver still records the mapping when an
            # inbound LID `pkmsg` establishes a fresh session.
            devices.extend(entry.devices)
        return [
            device
            for device in _dedupe_devices(devices)
            if not _same_full_jid(device, self._own_jid)
        ]

    async def _resolve_signal_address(self, peer: JID) -> JID:
        """Return the JID we should use as both participant `<to jid>`
        and Signal session key for outbound encryption.

        Earlier this method resolved PN -> LID before encryption: we'd
        USync the peer to learn the LID, build the X3DH session under
        the LID-keyed bundle, key the Signal session under LID, and
        ship the participant `<to jid="...">` as LID. End-to-end live
        testing showed that path consistently fails delivery — the
        server ACKs our outer stanza but the recipient's WhatsApp
        never displays the message.

        Until we understand exactly what extra glue Baileys does for
        LID-keyed outbound (likely: use LID-aware addressing in the
        prekey fetch iq, or carry a different `recipient`/`participant`
        attr, or attach the PN identity in `<device-identity>` even
        when encrypting under LID), keep outbound on PN throughout.
        Inbound LID still works fine: pkmsg from a LID peer
        establishes a fresh LID-keyed session locally; the LID map
        and PN<->LID migration helpers stay in place for the inbound
        side and for when we revisit LID-keyed outbound.
        """
        return peer

    def _remember_lid_mapping(self, pn: JID, lid: JID | None) -> str | None:
        if pn.server == "lid" or lid is None:
            return None
        self._lid_map.set(pn.user, lid.user)
        self._migrate_pn_session_to_lid(pn, JID(user=lid.user, server="lid", device=pn.device))
        return lid.user

    def _migrate_pn_session_to_lid(self, pn: JID, lid: JID) -> None:
        moved = migrate_pn_session_to_lid(
            sessions=self._sessions,
            identity_store=self._identity_store,
            pn=pn,
            lid=lid,
        )
        if not moved:
            return
        meta = self._peer_meta.pop(session_id(pn), None)
        if meta is not None:
            self._peer_meta[session_id(lid)] = meta

    def _retry_peer_from_signal(self, signal: RetrySignal, fallback: list[JID]) -> JID:
        for key in ("participant", "to", "recipient", "jid"):
            raw = signal.attrs.get(key)
            if raw:
                return _jid_from_attr(raw)
        if len(fallback) == 1:
            return fallback[0]
        return fallback[0] if fallback else self._own_jid

    def _build_participant_node(
        self, jid: JID, enc_type: str, ciphertext: bytes, count: int | None = None
    ) -> Node:
        enc_attrs: dict[str, AttrValue] = {"v": self._config.enc_version, "type": enc_type}
        if count is not None:
            enc_attrs["count"] = str(count)
        return Node(
            tag="to",
            attrs={"jid": jid},
            content=[
                Node(
                    tag="enc",
                    attrs=enc_attrs,
                    content=ciphertext,
                )
            ],
        )

    def _build_message_node(
        self,
        *,
        message_id: str,
        to: JID,
        participants: list[Node],
        message_type: str | None = None,
        edit: str | None = None,
    ) -> Node:
        content: list[Node] = [Node(tag="participants", content=participants)]
        if self._adv_signed_device_identity:
            content.append(
                Node(
                    tag="device-identity",
                    content=self._adv_signed_device_identity,
                )
            )
        attrs: dict[str, AttrValue] = {
            "id": message_id,
            "to": to,
            "type": message_type or self._config.message_type,
        }
        if edit is not None:
            attrs["edit"] = edit
        return Node(tag="message", attrs=attrs, content=content)

    @staticmethod
    def build_usync_node(message_id: str, peer: JID) -> Node:
        """Build the ``iq get`` stanza used to fetch a peer's prekey bundle.

        The exact schema used by the server is not publicly documented.
        This stanza follows the shape described in public writeups: an
        outer ``<iq type="get" xmlns="usync">`` with a ``<usync>`` child
        that carries a ``<list>`` of ``<user>`` elements. Callers are
        free to build their own if the server rejects this shape.
        """
        user = Node(tag="user", attrs={"jid": peer})
        lst = Node(tag="list", content=[user])
        usync = Node(
            tag="usync",
            attrs={
                "sid": message_id,
                "mode": "query",
                "last": "true",
                "index": "0",
                "context": "message",
            },
            content=[
                lst,
                Node(tag="query", content=[Node(tag="devices"), Node(tag="key"), Node(tag="lid")]),
            ],
        )
        return Node(
            tag="iq",
            attrs={
                "id": message_id,
                "type": "get",
                "xmlns": "usync",
                "to": JID(user="", server="s.whatsapp.net"),
            },
            content=[usync],
        )


# --- helpers --------------------------------------------------------


async def _single_device_fetcher(users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
    return {_base_jid(jid): UserSyncEntry(devices=[_base_jid(jid)]) for jid in users}


def _dedupe_devices(devices: Iterable[JID]) -> list[JID]:
    seen: set[tuple[str, str, int]] = set()
    out: list[JID] = []
    for jid in devices:
        key = (jid.user, jid.server, jid.device)
        if key in seen:
            continue
        seen.add(key)
        out.append(jid)
    return out


def _base_jid(jid: JID) -> JID:
    return JID(user=jid.user, server=jid.server, device=0)


def _same_full_jid(a: JID, b: JID) -> bool:
    return a.user == b.user and a.server == b.server and a.device == b.device


def _jid_from_attr(attr: object) -> JID:
    if isinstance(attr, JID):
        return attr
    if isinstance(attr, str) and attr:
        local, _, server = attr.partition("@")
        user, _, dev = local.partition(".")
        return JID(
            user=user,
            server=server or "s.whatsapp.net",
            device=int(dev) if dev.isdigit() else 0,
        )
    return JID(user="", server="s.whatsapp.net")


def _fmt_jid(jid: JID) -> str:
    return str(jid)
