# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Inbound frame reader: decrypt, dispatch, and emit events.

The :class:`Receiver` runs as a single asyncio task for the duration of
a connected session. Each loop iteration:

    1. Pulls one decrypted-by-Noise payload from the transport.
    2. Decodes it into a :class:`pywhats.binary.Node` tree.
    3. Dispatches by the outer tag:

       * ``message`` -> Signal-decrypts the ``<enc>`` child, unpacks the
         ``Message`` protobuf, emits a ``message`` event, and sends a
         ``<receipt type="delivery">`` stanza back so the server stops
         retransmitting.
       * ``ack`` -> threads the result into the sender's ack router so a
         pending ``send_text`` future can resolve.
       * ``iq`` -> completes a future in the pending-iq map (used by the
         prekey-bundle fetcher).
       * ``receipt`` -> logged only; delivery-ack accounting and read
         receipts are phase 2.
       * Anything else -> logged and skipped, not crashed.

    4. On any non-fatal exception inside the loop body, logs the error
       with context and keeps going. Only :class:`asyncio.CancelledError`
       and the transport-closed signal tear the loop down.

    5. Signal-decrypt failures emit a ``decrypt_error`` event carrying
       the message id (if it could be parsed out of the outer stanza)
       and a short reason string, then move on.

The receiver side of a pkmsg establishes a fresh Signal session: we run
:func:`x3dh_responder` against our signed prekey and, if one was used,
the referenced one-time prekey, then initialise a Bob-side ratchet and
immediately decrypt the inner SignalMessage. Subsequent ``msg`` frames
reuse that session.

Prose references consulted (no reference-implementation source read):

* Public WhatsApp multi-device protocol writeups describing the
  ``<message ...><enc v type>...</enc></message>`` stanza shape and
  the two ``enc.type`` values (``pkmsg`` for a new session,
  ``msg`` for an established one), plus the shape of the delivery
  ``<receipt>`` stanza.
* The Signal X3DH and Double Ratchet specifications
  (https://signal.org/docs/).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from typing import Protocol

from pywhats.appstate import AppStateKeyStore, AppStateSyncKey
from pywhats.binary import Node, decode, encode
from pywhats.binary.jid import parse_jid
from pywhats.binary.node import AttrValue
from pywhats.errors import ConnectionClosed
from pywhats.events import JID, Message
from pywhats.proto import Message as MessageProto
from pywhats.signal.experimental import (
    IdentityStore,
    InMemoryIdentityStore,
    InMemoryLidMap,
    LidMap,
    PreKeyBundle,
    SessionStore,
    SignedPreKey,
    ratchet_decrypt,
    ratchet_init_bob,
    x3dh_responder,
)
from pywhats.signal.experimental.keys import IdentityKeyPair, OneTimePreKey
from pywhats.signal.experimental.sender_key import (
    SenderKeyStore,
    group_decrypt,
    process_distribution_message,
)
from pywhats.signal.experimental.types import (
    PreKeySignalMessage,
    SignalMessage,
)

from .addressing import migrate_pn_session_to_lid, session_id
from .padding import unpad_random_max16
from .router import AckRouter

_log = logging.getLogger("pywhats.messaging.receiver")


# --- interface types -------------------------------------------------


class NoiseTransportRecvProtocol(Protocol):
    """The subset of :class:`pywhats.socket.noise.NoiseTransport` we need."""

    async def recv(self) -> bytes: ...

    async def send(self, plaintext: bytes) -> None: ...


class ResponderIdentityProvider(Protocol):
    """Responder-side Signal identity + prekey provider.

    The receiver uses this to resolve the local long-term identity
    keypair and any signed / one-time prekey referenced by the peer's
    first-message :class:`PreKeySignalMessage`.
    """

    @property
    def identity_private(self) -> bytes: ...

    @property
    def identity_public(self) -> bytes: ...

    def get_signed_pre_key(self, key_id: int) -> SignedPreKey: ...

    def get_one_time_pre_key(self, key_id: int) -> OneTimePreKey | None: ...


EventEmitter = Callable[..., Awaitable[None]]


class RetryReceiptHandler(Protocol):
    async def handle_retry_receipt(
        self,
        message_id: str,
        peer: JID,
        bundle: PreKeyBundle | None = None,
        count: int = 1,
    ) -> None: ...


class SuccessHandler(Protocol):
    """Hook fired when the server sends ``<success>`` after login.

    Implementations run the post-login activation flow (passive/active
    iq, unified_session, presence, app-level ping). Implemented by
    :class:`pywhats.messaging.activator.SessionActivator` in production.
    """

    async def on_success(self, node: Node) -> None: ...


class IbHandler(Protocol):
    """Hook for individual ``<ib>`` server-info-broadcast stanzas.

    The receiver does not blanket-ack ``<ib>`` because the server's
    expected response varies by child element (``edge_routing`` is
    store-only, ``offline_preview`` requires an ``<offline_batch>``
    reply, etc.). Production wiring lives in
    :class:`pywhats.messaging.ib.IbDispatcher`.
    """

    async def handle_ib(self, node: Node) -> None: ...


# --- pending iq map --------------------------------------------------


@dataclass
class PendingIqMap:
    """Correlates outbound ``<iq id=...>`` stanzas to response futures."""

    _pending: dict[str, asyncio.Future[Node]]

    def __init__(self) -> None:
        self._pending = {}

    def register(self, iq_id: str) -> asyncio.Future[Node]:
        if iq_id in self._pending:
            raise ValueError(f"iq id already pending: {iq_id!r}")
        fut: asyncio.Future[Node] = asyncio.get_event_loop().create_future()
        self._pending[iq_id] = fut
        return fut

    def cancel(self, iq_id: str) -> None:
        fut = self._pending.pop(iq_id, None)
        if fut is not None and not fut.done():
            fut.cancel()

    def resolve(self, iq_id: str, node: Node) -> bool:
        fut = self._pending.pop(iq_id, None)
        if fut is not None and not fut.done():
            fut.set_result(node)
            return True
        return False

    def pending_ids(self) -> list[str]:
        return list(self._pending.keys())


# --- receiver --------------------------------------------------------


class Receiver:
    """Reader task that decrypts inbound frames and dispatches them."""

    def __init__(
        self,
        *,
        transport: NoiseTransportRecvProtocol,
        router: AckRouter,
        iq_map: PendingIqMap,
        session_store: SessionStore,
        identity: ResponderIdentityProvider,
        emit: EventEmitter,
        own_jid: JID,
        retry_handler: RetryReceiptHandler | None = None,
        success_handler: SuccessHandler | None = None,
        ib_handler: IbHandler | None = None,
        identity_store: IdentityStore | None = None,
        lid_map: LidMap | None = None,
        atomic: Callable[[], AbstractContextManager[None]] | None = None,
        app_state_keys: AppStateKeyStore | None = None,
        server_sync_handler: Callable[[Node], Coroutine[object, object, None]] | None = None,
        history_sync_handler: Callable[[object], Coroutine[object, object, None]] | None = None,
        sender_key_store: SenderKeyStore | None = None,
    ) -> None:
        self._transport = transport
        self._router = router
        self._iq_map = iq_map
        self._sessions = session_store
        self._identity = identity
        self._emit = emit
        self._own_jid = own_jid
        self._retry_handler = retry_handler
        self._success_handler = success_handler
        self._ib_handler = ib_handler
        self._identity_store: IdentityStore = identity_store or InMemoryIdentityStore()
        self._lid_map: LidMap = lid_map or InMemoryLidMap()
        # Groups related store writes (ratchet session + peer identity +
        # consumed OPK) into one transaction when the stores share a
        # backend (SqliteStore.transaction); defaults to no-op for the
        # in-memory stores.
        self._atomic: Callable[[], AbstractContextManager[None]] = atomic or nullcontext
        self._app_state_keys = app_state_keys
        self._server_sync_handler = server_sync_handler
        self._history_sync_handler = history_sync_handler
        self._sender_key_store = sender_key_store

    # --- public API ---------------------------------------------------

    async def run(self) -> None:
        """Main loop. Terminates on transport close or cancellation."""
        _log.info("receiver: started")
        try:
            while True:
                try:
                    frame = await self._transport.recv()
                except ConnectionClosed as exc:
                    _log.info("receiver: transport closed: %s", exc)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    _log.exception("receiver: unexpected transport error; stopping")
                    return

                try:
                    await self._handle_frame(frame)
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    _log.exception("receiver: error handling frame; continuing")
        finally:
            _log.info("receiver: stopped")

    # --- frame dispatch ----------------------------------------------

    async def _handle_frame(self, frame: bytes) -> None:
        try:
            node = decode(frame)
        except Exception:  # noqa: BLE001
            _log.warning("receiver: undecodable frame (%d bytes); skipping", len(frame))
            return

        tag = node.tag
        if tag == "message":
            await self._handle_message(node)
        elif tag == "ack":
            self._handle_ack(node)
        elif tag == "iq":
            await self._handle_iq(node)
        elif tag == "receipt":
            await self._handle_receipt(node)
        elif tag == "success":
            if self._success_handler is not None:
                # Run the post-success activation in a background task
                # so frame dispatch keeps draining; the activator does
                # its own iq/await and ping loop.
                asyncio.create_task(
                    self._success_handler.on_success(node),
                    name="pywhats-on-success",
                )
            else:
                _log.debug("receiver: <success> received but no success_handler wired")
        elif tag == "ib":
            if self._ib_handler is not None:
                await self._ib_handler.handle_ib(node)
            else:
                _log.debug("receiver: ib id=%s type=%s", node.get_str("id"), node.get_str("type"))
        elif tag == "presence":
            await self._handle_presence(node)
        elif tag == "chatstate":
            await self._handle_chatstate(node)
        elif tag == "offline":
            _log.debug("receiver: offline id=%s", node.get_str("id"))
        elif tag == "notification":
            _log.debug(
                "receiver: notification id=%s type=%s",
                node.get_str("id"),
                node.get_str("type"),
            )
            if node.get_str("type") == "server_sync" and self._server_sync_handler is not None:
                # Run the app-state fetch in the background: it sends its own
                # <iq> and awaits the reply, which arrives on THIS receiver
                # loop — awaiting inline would deadlock. whatsmeow likewise
                # runs `go cli.FetchAppState` (handleAppStateNotification).
                asyncio.create_task(
                    self._server_sync_handler(node),
                    name="pywhats-server-sync",
                )
            await self._send_ack(node)
        elif tag == "failure":
            await self._handle_failure(node)
        elif tag == "stream:error":
            code = node.get_str("code")
            _log.warning(
                "receiver: <stream:error> code=%s attrs=%s children=%s",
                code,
                dict(node.attrs),
                [c.tag for c in node.get_children()],
            )
            # Terminal codes mirror the <failure> path: 401 (device
            # removed / conflict takeover) and 403 (banned) mean the
            # session is dead and the caller must re-pair. 515 is the
            # post-pair "reconnect now" signal (client.py) and any other
            # code stays log-only.
            if code in ("401", "403"):
                await self._safe_emit("logged_out", code)
        else:
            _log.debug("receiver: ignoring unknown stanza tag=%r", tag)

    async def _handle_failure(self, node: Node) -> None:
        """Surface a server ``<failure>`` login rejection.

        WhatsApp closes the socket right after sending this, so without
        handling it the disconnect looks silent. ``reason`` is a numeric
        code; ``401`` (device logged out / unlinked) and ``403``
        (forbidden / banned) are terminal — the linked-device entry is
        gone and the caller must re-pair. We log every failure and emit a
        ``logged_out`` event carrying the reason for the terminal codes.
        """
        reason = node.get_str("reason") or "?"
        location = node.get_str("location")
        _log.error(
            "receiver: server <failure> reason=%s location=%s — login rejected",
            reason,
            location,
        )
        if reason in ("401", "403"):
            await self._safe_emit("logged_out", reason)

    # --- <message> ---------------------------------------------------

    async def _handle_message(self, node: Node) -> None:
        message_id = node.get_str("id")
        from_attr = node.attrs.get("from")
        sender_jid = _jid_from_attr(from_attr)
        if sender_jid.server == "g.us":
            await self._handle_group_message(node, group=sender_jid)
            return
        if sender_jid.user == "status" and sender_jid.server == "broadcast":
            # Status updates are sender-key (skmsg) encrypted and we hold
            # no status sender-key session; prekey churn also yields
            # unknown-OPK pkmsgs. Both are expected — skip quietly rather
            # than emitting decrypt_error / retry receipts.
            _log.debug("receiver: ignoring status@broadcast message id=%s", message_id)
            return
        chat_jid = sender_jid  # 1-1 chat.
        # Learn the peer's PN<->LID pairing from the stanza before decrypt,
        # so a LID-addressed message can migrate an existing PN session.
        self._record_peer_addressing(node, sender_jid)
        try:
            timestamp = int(node.get_str("t") or "0")
        except ValueError:
            timestamp = 0

        enc = self._select_enc_node(node)
        if enc is None:
            _log.warning("receiver: message id=%s missing matching <enc> child", message_id)
            return

        enc_type = enc.get_str("type")
        ciphertext = enc.content_bytes()

        try:
            plaintext = self._decrypt_enc(sender_jid, enc_type, ciphertext)
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "receiver: decrypt failed id=%s from=%s type=%s: %s",
                message_id,
                sender_jid,
                enc_type,
                exc,
            )
            await self._safe_emit("decrypt_error", message_id, str(exc))
            # Best-effort retry receipt: tell the peer "I couldn't decode
            # this; please re-init the session and resend with a pkmsg".
            # Without this, peers that send us a `msg` we don't have a
            # session for will keep silently retrying forever and the
            # user never sees the message.
            try:
                await self._send_retry_receipt(node, sender=sender_jid)
            except Exception:  # noqa: BLE001
                _log.exception("receiver: failed to send retry receipt id=%s", message_id)
            return

        try:
            unpadded = unpad_random_max16(plaintext)
        except ValueError as exc:
            _log.warning(
                "receiver: bad WA padding id=%s len=%d: %s",
                message_id,
                len(plaintext),
                exc,
            )
            await self._safe_emit("decrypt_error", message_id, f"pad: {exc}")
            return

        try:
            proto = MessageProto()
            proto.ParseFromString(unpadded)
            text = _extract_text(proto)
        except Exception as exc:  # noqa: BLE001
            _log.warning("receiver: unparseable message proto id=%s: %s", message_id, exc)
            await self._safe_emit("decrypt_error", message_id, f"proto: {exc}")
            return

        handled_protocol = self._handle_protocol_message(proto, sender_jid)

        if not text and not handled_protocol:
            # Some Message body variants aren't modelled in our proto
            # subset yet (DSM wrapper, ephemeral, view-once, edits,
            # media captions, etc.). Log the raw bytes so we can grow
            # `_extract_text` to cover whatever the peer actually sent.
            # Handled protocol messages are excluded: a key share's raw
            # bytes are key material and must never hit the log.
            _log.info(
                "receiver: empty text id=%s len=%d hex=%s",
                message_id,
                len(unpadded),
                unpadded.hex(),
            )

        message = Message(
            id=message_id,
            chat=chat_jid,
            sender=sender_jid,
            text=text,
            timestamp=timestamp,
            from_me=False,
        )
        await self._safe_emit("message", message)

        # Best-effort delivery receipt. We never let a receipt send
        # failure abort frame processing: the event was already emitted
        # to user handlers, and the server will retransmit if it cares.
        try:
            await self._send_delivery_receipt(node, to=sender_jid)
        except Exception:  # noqa: BLE001
            _log.exception(
                "receiver: failed to send delivery receipt id=%s; continuing", message_id
            )

    async def _handle_group_message(self, node: Node, *, group: JID) -> None:
        """Decrypt a group ``skmsg``, first ingesting any SKDM it carries.

        A group message from a new sender carries both a ``pkmsg`` (the
        1:1-encrypted SenderKeyDistributionMessage) and the ``skmsg`` (the
        group content). We process the SKDM to establish the sender-key
        session, then decrypt the skmsg with it. Mirrors whatsmeow's group
        message decrypt path (message.go).
        """
        if self._sender_key_store is None:
            _log.debug("receiver: group message but no sender-key store; ignoring")
            return
        message_id = node.get_str("id")
        participant = _jid_from_attr(node.attrs.get("participant"))
        try:
            timestamp = int(node.get_str("t") or "0")
        except ValueError:
            timestamp = 0

        # First: ingest any SKDM carried in a pkmsg/msg <enc> so the
        # sender-key session exists before we decrypt the skmsg.
        for enc in node.get_children("enc"):
            if enc.get_str("type") in ("pkmsg", "msg"):
                self._ingest_group_skdm(enc, group, participant)

        skmsg_enc = next(
            (e for e in node.get_children("enc") if e.get_str("type") == "skmsg"), None
        )
        if skmsg_enc is None:
            return

        state = self._sender_key_store.load(str(group), session_id(participant))
        if state is None:
            _log.info(
                "receiver: no sender-key for group=%s participant=%s; cannot decrypt id=%s",
                group,
                participant,
                message_id,
            )
            await self._safe_emit("decrypt_error", message_id, "no sender key")
            return
        try:
            plaintext, new_state = group_decrypt(state, skmsg_enc.content_bytes())
            self._sender_key_store.save(str(group), session_id(participant), new_state)
            unpadded = unpad_random_max16(plaintext)
            proto = MessageProto()
            proto.ParseFromString(unpadded)
            text = _extract_text(proto)
        except Exception as exc:  # noqa: BLE001
            _log.warning("receiver: group decrypt failed id=%s: %s", message_id, exc)
            await self._safe_emit("decrypt_error", message_id, f"skmsg: {exc}")
            return

        message = Message(
            id=message_id,
            chat=group,
            sender=participant,
            text=text,
            timestamp=timestamp,
            from_me=False,
        )
        await self._safe_emit("message", message)
        try:
            await self._send_delivery_receipt(node, to=group)
        except Exception:  # noqa: BLE001
            _log.exception("receiver: failed to send group delivery receipt id=%s", message_id)

    def _ingest_group_skdm(self, enc: Node, group: JID, participant: JID) -> None:
        """Decrypt a pkmsg/msg carrying a SenderKeyDistributionMessage and store it."""
        try:
            plaintext = self._decrypt_enc(participant, enc.get_str("type"), enc.content_bytes())
            proto = MessageProto()
            proto.ParseFromString(unpad_random_max16(plaintext))
        except Exception as exc:  # noqa: BLE001
            _log.debug("receiver: group SKDM decrypt failed: %s", exc)
            return
        if not proto.HasField("sender_key_distribution_message"):
            return
        skdm = proto.sender_key_distribution_message
        axolotl = skdm.axolotl_sender_key_distribution_message
        if not axolotl:
            return
        try:
            state = process_distribution_message(bytes(axolotl))
        except Exception as exc:  # noqa: BLE001
            _log.warning("receiver: failed to process group SKDM: %s", exc)
            return
        assert self._sender_key_store is not None
        self._sender_key_store.save(str(group), session_id(participant), state)
        _log.info("receiver: stored sender key for group=%s participant=%s", group, participant)

    def _handle_protocol_message(self, proto: MessageProto, sender: JID) -> bool:
        """Handle the ``protocol_message`` shapes we support; True if recognised.

        Mirrors whatsmeow ``handleProtocolMessage`` (message.go): protocol
        messages are only trusted from ourselves (``info.IsFromMe``). An
        ``APP_STATE_SYNC_KEY_SHARE`` persists every carried key
        (``handleAppStateSyncKeyShare``); a ``HISTORY_SYNC_NOTIFICATION``
        hands off to the history syncer to download + parse the blob. The
        message itself still flows on to the normal event + receipt path,
        as in whatsmeow.
        """
        if not proto.HasField("protocol_message"):
            return False
        pm = proto.protocol_message
        from_self = sender.user == self._own_jid.user
        handled = False

        if self._app_state_keys is not None and pm.HasField("app_state_sync_key_share"):
            handled = True
            if from_self:
                self._store_app_state_keys(pm.app_state_sync_key_share.keys)
            else:
                _log.warning("receiver: ignoring app-state key share from non-self %s", sender)

        if self._history_sync_handler is not None and pm.HasField("history_sync_notification"):
            handled = True
            if from_self:
                asyncio.create_task(
                    self._history_sync_handler(pm.history_sync_notification),
                    name="pywhats-history-sync",
                )
            else:
                _log.warning("receiver: ignoring history sync from non-self %s", sender)

        return handled

    def _store_app_state_keys(self, keys: object) -> None:
        assert self._app_state_keys is not None
        try:
            # All keys land together (43 in the live capture) — a crash
            # partway must not leave a half-stored share.
            with self._atomic():
                for key in keys:  # type: ignore[attr-defined]
                    self._app_state_keys.put(
                        AppStateSyncKey(
                            key_id=key.key_id.key_id,
                            key_data=key.key_data.key_data,
                            fingerprint=key.key_data.fingerprint.SerializeToString(),
                            timestamp=key.key_data.timestamp,
                        )
                    )
        except Exception:  # noqa: BLE001
            _log.exception("receiver: failed to store app-state sync keys; continuing")
            return
        _log.info("receiver: stored %d app-state sync keys", len(keys))  # type: ignore[arg-type]

    def _select_enc_node(self, node: Node) -> Node | None:
        flat = node.get_child("enc")
        if flat is not None:
            return flat

        participants = node.get_child("participants")
        if participants is None:
            return None
        for to_node in participants.get_children("to"):
            jid = _jid_from_attr(to_node.get_attr("jid"))
            if _same_full_jid(jid, self._own_jid):
                return to_node.get_child("enc")
        return None

    def _decrypt_enc(self, sender: JID, enc_type: str, ciphertext: bytes) -> bytes:
        self._migrate_known_lid_sender(sender)
        sid = session_id(sender)
        # X3DH 3.3: AD = Encode(IKA) || Encode(IKB). On the responder
        # side IKA is the peer's long-term key (carried in the pkmsg on
        # the first message, then cached on the session) and IKB is our
        # own identity public.
        if enc_type == "pkmsg":
            pkmsg = PreKeySignalMessage.decode(ciphertext)
            spk = self._identity.get_signed_pre_key(pkmsg.signed_pre_key_id)
            opk: OneTimePreKey | None = None
            if pkmsg.one_time_pre_key_id is not None:
                opk = self._identity.get_one_time_pre_key(pkmsg.one_time_pre_key_id)
                if opk is None:
                    raise ValueError(f"unknown one-time pre-key id {pkmsg.one_time_pre_key_id}")
            identity = IdentityKeyPair(
                private=self._identity.identity_private,
                public=self._identity.identity_public,
            )
            result = x3dh_responder(
                identity,
                spk,
                opk,
                pkmsg.identity_key,
                pkmsg.base_key,
            )
            state = ratchet_init_bob(result.shared_secret, spk.private, spk.public)
            ad = pkmsg.identity_key + self._identity.identity_public
            plaintext = ratchet_decrypt(
                state,
                pkmsg.message.header,
                pkmsg.message.ciphertext,
                ad,
                verify_mac=lambda mac_key: pkmsg.message.verify_mac(
                    pkmsg.identity_key,
                    self._identity.identity_public,
                    mac_key,
                ),
            )
            # The consumed OPK, the new session, and the pinned peer
            # identity must land together — a crash between them would
            # leave a session without its identity (or burn the OPK
            # without keeping the session it established).
            with self._atomic():
                if pkmsg.one_time_pre_key_id is not None:
                    _consume_opk(self._identity, pkmsg.one_time_pre_key_id)
                self._sessions.save(sid, state)
                self._identity_store.save(sid, pkmsg.identity_key)
            return plaintext

        if enc_type == "msg":
            loaded = self._sessions.load(sid)
            if loaded is None:
                raise ValueError(f"no session for peer {sender}")
            state = loaded
            peer_identity = self._identity_store.load(sid)
            if peer_identity is None:
                raise ValueError(f"no cached peer identity for {sender}")
            inner = SignalMessage.decode(ciphertext)
            ad = peer_identity + self._identity.identity_public
            plaintext = ratchet_decrypt(
                state,
                inner.header,
                inner.ciphertext,
                ad,
                verify_mac=lambda mac_key: inner.verify_mac(
                    peer_identity,
                    self._identity.identity_public,
                    mac_key,
                ),
            )
            self._sessions.save(sid, state)
            return plaintext

        raise ValueError(f"unsupported enc.type {enc_type!r}")

    def _record_peer_addressing(self, node: Node, sender: JID) -> None:
        """Record the peer's PN<->LID pairing from the message stanza.

        Mirrors whatsmeow ``parseMessageSource`` + ``StoreLIDPNMapping``
        (message.go): a 1:1 message addressed by LID carries a ``sender_pn``
        attribute, and one addressed by PN carries ``sender_lid``. WhatsApp
        is migrating to LID addressing, so a peer we first talked to over PN
        may later reach us over LID; recording the pairing lets
        :meth:`_migrate_known_lid_sender` reuse the existing PN session
        instead of failing with "no session".

        whatsmeow also defaults the alternate address's device to the
        sender's device when the stanza omits it (message.go: ``if
        !source.SenderAlt.IsEmpty() && source.SenderAlt.Device == 0``); the
        LID map is keyed by user only, so that detail does not matter here.
        """
        if sender.server == "lid":
            alt = _jid_from_attr(node.attrs.get("sender_pn"))
            if alt.user and alt.server != "lid":
                self._lid_map.set(alt.user, sender.user)
        elif sender.server == "s.whatsapp.net":
            alt = _jid_from_attr(node.attrs.get("sender_lid"))
            if alt.user and alt.server == "lid":
                self._lid_map.set(sender.user, alt.user)

    def _migrate_known_lid_sender(self, sender: JID) -> None:
        if sender.server != "lid" or self._sessions.load(session_id(sender)) is not None:
            return
        pn_user = self._lid_map.get_pn(sender.user)
        if pn_user is None:
            return
        pn = JID(user=pn_user, server="s.whatsapp.net", device=sender.device)
        # The migration touches both stores four times (copy session +
        # identity to the LID key, delete the PN pair); commit as one.
        with self._atomic():
            migrate_pn_session_to_lid(
                sessions=self._sessions,
                identity_store=self._identity_store,
                pn=pn,
                lid=sender,
            )

    async def _send_ack(self, node: Node) -> None:
        ack = _build_ack_node(node, own_jid=self._own_jid)
        frame = encode(ack)
        await self._transport.send(frame)
        _log.debug("receiver: sent ack id=%s class=%s", ack.get_str("id"), ack.get_str("class"))

    async def _send_retry_receipt(self, node: Node, *, sender: JID) -> None:
        """Send a minimal ``<receipt type="retry">`` back to the peer.

        Baileys' real ``sendRetryRequest`` carries a ``<keys>`` bundle
        with our identity, signed prekey, OPK, and device-identity so
        the peer can re-establish a session without re-fetching from
        the server. We don't ship those keys yet (prekey upload over
        ``xmlns="encrypt"`` is a separate task), so this is the bare
        receipt: ``<retry count id t v error/>`` plus
        ``<registration>`` carrying our 4-byte big-endian regid. WA
        accepts it as a "please resend" signal even without keys; the
        peer will USync us and re-fetch if needed.
        """
        message_id = node.get_str("id")
        if not message_id:
            return
        regid = getattr(self._identity, "registration_id", None)
        children: list[Node] = [
            Node(
                tag="retry",
                attrs={
                    "count": "1",
                    "id": message_id,
                    "t": node.get_str("t") or "0",
                    "v": "1",
                },
            )
        ]
        if isinstance(regid, int):
            children.append(Node(tag="registration", content=int(regid).to_bytes(4, "big")))
        attrs: dict[str, AttrValue] = {
            "id": message_id,
            "type": "retry",
            "to": sender,
        }
        if "participant" in node.attrs:
            attrs["participant"] = node.attrs["participant"]
        receipt = Node(tag="receipt", attrs=attrs, content=children)
        await self._transport.send(encode(receipt))
        _log.info(
            "receiver: sent retry receipt id=%s to=%s",
            message_id,
            sender,
        )

    async def _send_delivery_receipt(self, node: Node, *, to: JID) -> None:
        attrs: dict[str, AttrValue] = {
            "id": node.get_str("id"),
            "type": "delivery",
            "to": to,
        }
        if "participant" in node.attrs:
            attrs["participant"] = node.attrs["participant"]
        receipt = Node(tag="receipt", attrs=attrs)
        await self._transport.send(encode(receipt))
        _log.debug("receiver: sent delivery receipt id=%s to=%s", receipt.get_str("id"), to)

    # --- <ack> -------------------------------------------------------

    async def _handle_presence(self, node: Node) -> None:
        """Surface a peer ``<presence>`` update as a ``presence`` event."""
        from .presence import parse_presence

        await self._safe_emit("presence", parse_presence(node))

    async def _handle_chatstate(self, node: Node) -> None:
        """Surface a peer ``<chatstate>`` typing update as a ``chat_presence`` event."""
        from .presence import parse_chat_presence

        await self._safe_emit("chat_presence", parse_chat_presence(node))

    async def _handle_receipt(self, node: Node) -> None:
        receipt_type = node.get_str("type")
        if receipt_type != "retry":
            # Delivery/read/played receipts for our sent messages: surface
            # as a `receipt` event (whatsmeow events.Receipt), then ack.
            from .presence import parse_receipt

            await self._safe_emit("receipt", parse_receipt(node))
            await self._send_ack(node)
            return
        msg_id = node.get_str("id")
        peer = _jid_from_attr(node.attrs.get("participant") or node.attrs.get("from"))
        retry_child = node.get_child("retry")
        count = _parse_int(retry_child.get_str("count", "1") if retry_child else "1", default=1)
        bundle: PreKeyBundle | None = None
        keys = node.get_child("keys")
        if keys is not None:
            try:
                bundle = _parse_retry_keys(keys)
            except Exception as exc:  # noqa: BLE001
                _log.warning("receiver: retry receipt keys parse failed id=%s: %s", msg_id, exc)
        if self._retry_handler is not None and msg_id and peer.user:
            await self._retry_handler.handle_retry_receipt(msg_id, peer, bundle, count)
        await self._send_ack(node)

    def _handle_ack(self, node: Node) -> None:
        ack_id = node.get_str("id")
        if not ack_id:
            _log.debug("receiver: ack without id; ignoring")
            return
        ack_class = node.get_str("class")
        # The server uses <ack class="message"> for successful delivery
        # and carries a separate <retry> stanza (or ack with error
        # attrs) for the retry path. We surface a retry whenever the
        # ack carries an ``error`` attribute or a nested <retry> child.
        retry_child = node.get_child("retry")
        has_error = "error" in node.attrs
        if retry_child is not None or has_error:
            attrs_out: dict[str, str] = {}
            if retry_child is not None:
                for k, v in retry_child.attrs.items():
                    attrs_out[k] = str(v)
            if has_error:
                attrs_out["error"] = str(node.attrs["error"])
            self._router.resolve_retry(ack_id, attrs_out)
            _log.debug("receiver: ack->retry id=%s class=%s", ack_id, ack_class)
            return
        self._router.resolve_ack(ack_id)
        _log.debug("receiver: ack->ok id=%s class=%s", ack_id, ack_class)

    # --- <iq> --------------------------------------------------------

    async def _handle_iq(self, node: Node) -> None:
        iq_id = node.get_str("id")
        if not iq_id:
            _log.debug("receiver: iq without id; ignoring")
            return
        iq_type = node.get_str("type")
        if iq_type in ("result", "error"):
            # A response to an iq WE sent (prekey fetch, usync, app ping…).
            if not self._iq_map.resolve(iq_id, node):
                _log.debug("receiver: unsolicited iq result id=%s; ignoring", iq_id)
            return
        # Server-initiated request (type="get"/"set"): XMPP requires a
        # response, and WhatsApp unlinks a companion that leaves a server
        # request — notably its ``urn:xmpp:ping`` iq — unanswered inside a
        # ~60 s grace window (observed live: WS CLOSE 1011 + device removed
        # at exactly T+60 s). The pairing loop already replies to these
        # (pairing.py:_ack_iq); this ports the same ack into the live
        # session. A bare ``<iq type="result">`` satisfies a ping and is
        # inert for anything else.
        await self._reply_server_iq(node)

    async def _reply_server_iq(self, node: Node) -> None:
        iq_id = node.get_str("id")
        attrs: dict[str, AttrValue] = {"type": "result", "id": iq_id}
        from_attr = node.attrs.get("from")
        if from_attr is not None:
            attrs["to"] = from_attr
        await self._transport.send(encode(Node(tag="iq", attrs=attrs)))
        _log.debug(
            "receiver: replied to server iq id=%s type=%s xmlns=%s",
            iq_id,
            node.get_str("type"),
            node.get_str("xmlns"),
        )

    # --- helpers -----------------------------------------------------

    async def _safe_emit(self, event: str, *args: object) -> None:
        try:
            await self._emit(event, *args)
        except Exception:  # noqa: BLE001
            _log.exception("receiver: handler for %r raised", event)


# --- helpers ---------------------------------------------------------


def _same_full_jid(a: JID, b: JID) -> bool:
    return a.user == b.user and a.server == b.server and a.device == b.device


def _jid_from_attr(attr: object) -> JID:
    if isinstance(attr, JID):
        return attr
    if isinstance(attr, str) and attr:
        # Fallback for stanzas that carry the ``from`` attr as a raw
        # string (e.g. test fixtures): parse ``user[.device]@server``.
        return parse_jid(attr)
    return JID(user="", server="s.whatsapp.net")


def _build_ack_node(node: Node, *, own_jid: JID, error_code: int | None = None) -> Node:
    attrs: dict[str, AttrValue] = {
        "id": node.get_str("id"),
        "to": node.attrs.get("from", JID(user="", server="s.whatsapp.net")),
        "class": node.tag,
    }
    if error_code is not None:
        attrs["error"] = str(error_code)
    for key in ("participant", "recipient", "type"):
        if key in node.attrs:
            attrs[key] = node.attrs[key]
    if node.tag == "message":
        attrs["from"] = own_jid
    return Node(tag="ack", attrs=attrs)


def _parse_retry_keys(keys: Node) -> PreKeyBundle:
    identity_key = _strip_signal_pubkey(_read_child_bytes(keys, "identity"))
    skey = keys.get_child("skey")
    if skey is None:
        raise ValueError("retry keys missing <skey>")
    spk_id = _read_int_be(skey, "id")
    spk_pub = _strip_signal_pubkey(_read_child_bytes(skey, "value"))
    spk_sig = _read_child_bytes(skey, "signature")

    opk_node = keys.get_child("key")
    opk_id: int | None = None
    opk_pub: bytes | None = None
    if opk_node is not None:
        opk_id = _read_int_be(opk_node, "id")
        opk_pub = _strip_signal_pubkey(_read_child_bytes(opk_node, "value"))

    bundle = PreKeyBundle(
        identity_key=identity_key,
        signed_pre_key_id=spk_id,
        signed_pre_key_public=spk_pub,
        signed_pre_key_signature=spk_sig,
        one_time_pre_key_id=opk_id,
        one_time_pre_key_public=opk_pub,
    )
    if not bundle.verify_signature():
        raise ValueError("retry keys SPK signature did not verify")
    return bundle


def _read_child_bytes(parent: Node, tag: str) -> bytes:
    child = parent.get_child(tag)
    if child is None:
        raise ValueError(f"missing <{tag}>")
    b = child.content_bytes()
    if not b:
        raise ValueError(f"empty <{tag}>")
    return b


def _read_int_be(parent: Node, tag: str) -> int:
    return int.from_bytes(_read_child_bytes(parent, tag), "big")


def _parse_int(raw: str, *, default: int) -> int:
    try:
        return int(raw)
    except ValueError:
        return default


def _strip_signal_pubkey(public: bytes) -> bytes:
    if len(public) == 33:
        if public[0] != 0x05:
            raise ValueError("invalid Signal public key type byte")
        return public[1:]
    if len(public) != 32:
        raise ValueError("invalid Signal public key length")
    return public


def _consume_opk(identity: ResponderIdentityProvider, key_id: int) -> None:
    consume = getattr(identity, "consume_one_time_pre_key", None)
    if callable(consume):
        consume(key_id)


def _extract_text(proto: MessageProto) -> str:
    """Pull the human-readable text out of a decrypted ``Message`` proto.

    Supports the two phase-1 shapes: ``conversation`` (plain text) and
    ``extended_text_message.text`` (text with link/format metadata).
    Anything else surfaces as an empty string; higher layers can
    inspect the raw proto if they care about media, reactions, etc.
    """
    conv = getattr(proto, "conversation", "") or ""
    if conv:
        return conv
    etm = getattr(proto, "extended_text_message", None)
    if etm is not None:
        text = getattr(etm, "text", "") or ""
        if text:
            return text
    return ""
