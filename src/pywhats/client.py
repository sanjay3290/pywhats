"""High-level Client API. Phase 1 skeleton — transport/handshake land in follow-ups."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from pywhats.errors import NotConnected, PairingFailed
from pywhats.events import JID, Message
from pywhats.store import DeviceStore, load_device_store

log = logging.getLogger(__name__)

Handler = Callable[..., Awaitable[None]]


class Client:
    """Async WhatsApp multi-device client.

    Phase 1 surface only: connect(), send_text(), on(event), wait_closed(),
    disconnect(). Media, groups, and appstate land in later phases.
    """

    def __init__(
        self,
        session_path: str | None = None,
        *,
        ws_url: str | None = None,
        media_http_get: Any = None,
        media_http_post: Any = None,
    ) -> None:
        self._session_path = session_path
        # Optional override for the websocket endpoint. Defaults to the
        # production WhatsApp edge when None; tests point this at a local
        # fake server. Additive-only: existing callers are unaffected.
        self._ws_url = ws_url
        # Optional media CDN HTTP overrides (tests inject fakes so media
        # download/upload can be exercised without hitting the real CDN).
        self._media_http_get = media_http_get
        self._media_http_post = media_http_post
        self._handlers: dict[str, list[Handler]] = {}
        self._closed = asyncio.Event()
        self._connected = False
        self._device: DeviceStore | None = None
        if session_path is not None:
            self._device = self._load_device(session_path)
        # Populated on connect(); cleared on disconnect.
        self._sock: Any = None
        self._transport: Any = None
        self._receiver: Any = None
        self._activator: Any = None
        self._app_state_syncer: Any = None
        self._media_downloader: Any = None
        self._media_uploader: Any = None
        self._history_syncer: Any = None
        self._send_iq: Any = None
        self._bg_task: asyncio.Task[None] | None = None
        # Set when the keepalive path force-closes the socket.
        self._fatal_task: asyncio.Task[None] | None = None
        # SQLite persistence handle (opened on connect when session_path is set).
        self._signal_store: Any = None

    @staticmethod
    def _load_device(session_path: str) -> DeviceStore | None:
        """Load an existing device store, or return ``None`` if absent.

        Any other error (corrupt JSON, schema mismatch, unsafe permissions)
        propagates — the caller must fix the file rather than silently
        re-pair with new credentials.
        """
        try:
            return load_device_store(session_path)
        except FileNotFoundError:
            return None

    @property
    def device(self) -> DeviceStore | None:
        """The currently-loaded device credentials, if any."""
        return self._device

    def _save_device(self) -> None:
        """Persist the current device store to ``session_path``, if configured."""
        if self._device is None or self._session_path is None:
            return
        self._device.save(self._session_path)

    def on(self, event: str) -> Callable[[Handler], Handler]:
        """Register an async handler for an event.

        Events: ``qr``, ``message``, ``connected``, ``disconnected``,
        ``paired``, ``decrypt_error``, and ``logged_out``. ``logged_out``
        fires with the server's reason code (e.g. ``"401"``) when the
        linked device has been removed and a fresh pairing is required.

        App-state sync (#35d) adds ``mute``, ``pin``, ``archive``,
        ``contact``, and ``pushname``, each carrying the matching
        :mod:`pywhats.events` payload (``Mute`` / ``Pin`` / ``Archive`` /
        ``Contact`` / ``PushName``). #38 adds ``receipt`` / ``presence`` /
        ``chat_presence``; #37 adds ``history_sync``. Group messages (#39)
        arrive on the same ``message`` event, with ``chat`` set to the
        ``@g.us`` JID and ``sender`` to the participant. 0.2.0 adds
        ``reaction`` (an emoji reaction to an existing message, carrying
        a :class:`pywhats.events.Reaction`), and ``message_edit`` /
        ``message_revoke`` (a peer edited or deleted an earlier message,
        carrying :class:`pywhats.events.MessageEdit` /
        :class:`pywhats.events.MessageRevoke`).
        """

        def decorator(fn: Handler) -> Handler:
            self._handlers.setdefault(event, []).append(fn)
            return fn

        return decorator

    async def _emit(self, event: str, *args: Any) -> None:
        for fn in self._handlers.get(event, ()):
            try:
                await fn(*args)
            except Exception:
                log.exception("handler for %r raised", event)

    async def connect(self) -> None:
        """Open the websocket, run the Noise handshake, and start reading frames.

        Routes into either the pairing flow (no stored credentials) or
        the login-resume flow (stored credentials present). The actual
        wiring to the transport is factored into
        :meth:`_run_pairing` / :meth:`_run_login` so tests can override
        them without mocking websockets.
        """
        if self._device is not None and self._device.jid is not None:
            await self._run_login()
        else:
            await self._run_pairing()

    async def _run_pairing(self) -> None:  # pragma: no cover - integration
        """Orchestrate a fresh QR pairing.

        The body here is a thin wrapper so unit tests can target
        :class:`pywhats.pairing.Pairer` directly while keeping the
        high-level ``Client.connect`` shape stable.
        """
        from pywhats.pairing import Pairer, build_register_payload, make_fresh_device
        from pywhats.socket.noise import NoiseHandshake
        from pywhats.socket.transport import NoiseSocket

        if self._device is None:
            self._device = make_fresh_device()

        sock = NoiseSocket(self._ws_url) if self._ws_url is not None else NoiseSocket()
        await sock.connect()
        # WA requires a 4-byte intro header `WA\x06\x03` before the first
        # Noise frame on the wire (sent once, then normal 3-byte framing).
        sock._intro_prefix = b"WA\x06\x03"
        try:
            handshake = NoiseHandshake(sock, client_static_private=self._device.noise_private)
            payload = build_register_payload(self._device)
            transport = await handshake.perform(payload)
            pairer = Pairer(transport=transport, device=self._device)

            async def _qr_handler(ref_payload: str) -> None:
                await self._emit("qr", ref_payload)

            result = await pairer.run(_qr_handler)
            # Persist only after the ADV signature has been verified.
            if self._session_path is not None:
                self._save_device()
            await self._emit("paired", result.jid)
        except PairingFailed:
            raise
        finally:
            # The server sends <stream:error code="515"/> right after a
            # successful pair-success — that's the signal to reconnect with
            # the login payload. Close the registration socket either way.
            await sock.disconnect()

        # Now reconnect under the login payload so the phone finalizes the
        # link and promotes us to the Linked Devices list.
        if self._device is not None and self._device.jid is not None:
            await self._run_login()

    async def _run_login(self) -> None:  # pragma: no cover - integration
        """Resume a session from stored credentials."""
        from pywhats.pairing import build_login_payload
        from pywhats.socket.noise import NoiseHandshake
        from pywhats.socket.transport import NoiseSocket

        assert self._device is not None
        sock = NoiseSocket(self._ws_url) if self._ws_url is not None else NoiseSocket()
        await sock.connect()
        # WA requires a 4-byte intro header `WA\x06\x03` before the first
        # Noise frame on the wire (sent once, then normal 3-byte framing).
        sock._intro_prefix = b"WA\x06\x03"
        try:
            handshake = NoiseHandshake(sock, client_static_private=self._device.noise_private)
            payload = build_login_payload(self._device)
            transport = await handshake.perform(payload)
            self._sock = sock
            self._transport = transport
            self._install_messaging(transport)
            self._connected = True
            await self._emit("connected")
            # Kick off the receiver task group (reader + any other bg
            # tasks) so inbound frames get dispatched as they arrive.
            self._bg_task = asyncio.create_task(self._run_background_tasks(), name="pywhats-bg")
        except Exception:
            await sock.disconnect()
            raise

    def _install_messaging(self, transport: Any) -> None:  # pragma: no cover - integration
        """Wire up the :class:`Sender` + :class:`Receiver` on a live transport."""
        from pywhats.messaging import (
            AckRouter,
            PendingIqMap,
            Receiver,
            Sender,
            SenderConfig,
            USyncDeviceFetcher,
        )
        from pywhats.messaging.ib import IbDispatcher
        from pywhats.messaging.prekey import PrekeyFetcher, PrekeyUploader

        assert self._device is not None
        device = self._device

        from pywhats.appstate.fetch import AppStateSyncer
        from pywhats.binary import encode as _encode
        from pywhats.media.download import MediaDownloader, default_http_get
        from pywhats.media.upload import MediaUploader, default_http_post
        from pywhats.messaging.ids import new_message_id

        router = AckRouter()
        iq_map = PendingIqMap()
        (
            sessions,
            ident_store,
            lid_map,
            prekey_store,
            app_state_keys,
            app_state_store,
            sender_key_store,
            atomic,
        ) = self._open_signal_stores()
        identity = _make_responder_identity(device, prekey_store)
        own_jid = _own_signal_jid(device)

        prekey_fetcher = PrekeyFetcher(transport, iq_map)
        device_fetcher = USyncDeviceFetcher(transport, iq_map)
        prekey_uploader = PrekeyUploader(
            transport=transport,
            iq_map=iq_map,
            registration_id=device.registration_id,
            identity_public=device.identity_public,
            signed_pre_key=device.signed_pre_key(),
            prekey_store=prekey_store,
        )

        sender = Sender(
            transport=transport,
            router=router,
            session_store=sessions,
            identity=identity,
            prekey_fetcher=prekey_fetcher,
            device_fetcher=device_fetcher,
            adv_signed_device_identity=device.adv_signed_device_identity,
            identity_store=ident_store,
            lid_map=lid_map,
            own_jid=own_jid,
            config=SenderConfig(),
            sender_key_store=sender_key_store,
        )
        self._install_sender(sender)

        activator = self._build_activator(
            transport=transport,
            iq_map=iq_map,
            device=device,
            upload_prekeys=prekey_uploader.refill_if_low,
        )
        self._activator = activator

        ib_dispatcher = IbDispatcher(
            transport=transport,
            on_routing_info=_log_unpersisted_routing_info,
        )

        # Media download (#36): an injected iq round-trip + HTTP GET. Also
        # backs app-state external-snapshot download so a full app-state
        # sync can decode the CDN-hosted snapshot blob (#35c).
        async def _send_iq(node: Any) -> Any:
            iq_id = node.get_str("id") or new_message_id()
            node.attrs["id"] = iq_id
            fut = iq_map.register(iq_id)
            try:
                await transport.send(_encode(node))
                return await fut
            finally:
                iq_map.cancel(iq_id)

        self._send_iq = _send_iq
        media_downloader = MediaDownloader(
            send_iq=_send_iq, http_get=self._media_http_get or default_http_get
        )
        self._media_downloader = media_downloader
        self._media_uploader = MediaUploader(
            send_iq=_send_iq, http_post=self._media_http_post or default_http_post
        )

        # History sync (#37): download + inflate + parse the
        # HISTORY_SYNC_NOTIFICATION blobs the phone self-sends at bootstrap.
        from pywhats.history import HistorySyncer

        history_syncer = HistorySyncer(downloader=media_downloader, emit=self._emit)
        self._history_syncer = history_syncer

        # App-state sync: react to server_sync notifications by fetching the
        # advertised collections from the stored version cursor (#35c), then
        # surface the decoded mutations as typed events (#35d). External
        # snapshot blobs are downloaded via the media downloader (#36).
        app_state_syncer = AppStateSyncer(
            transport=transport,
            iq_map=iq_map,
            key_store=app_state_keys,
            app_state_store=app_state_store,
            download_external=media_downloader.download_external_blob,
            on_mutations=self._emit_app_state_events,
        )
        self._app_state_syncer = app_state_syncer

        receiver = Receiver(
            transport=transport,
            router=router,
            iq_map=iq_map,
            session_store=sessions,
            identity=identity,
            emit=self._emit,
            own_jid=own_jid,
            retry_handler=sender,
            success_handler=activator,
            ib_handler=ib_dispatcher,
            identity_store=ident_store,
            lid_map=lid_map,
            atomic=atomic,
            app_state_keys=app_state_keys,
            server_sync_handler=app_state_syncer.handle_server_sync,
            history_sync_handler=history_syncer.handle,
            sender_key_store=sender_key_store,
        )
        self._receiver = receiver

    def _open_signal_stores(
        self,
    ) -> tuple[Any, Any, Any, Any, Any, Any, Any, Any]:  # pragma: no cover
        """Return ``(sessions, identities, lid_map, prekeys, app_state_keys,
        app_state, sender_keys, atomic)``.

        Persist Signal sessions, peer identity public keys, the PN<->LID
        map, our own one-time prekeys, the app-state sync keys, and the
        app-state version/mutation-MAC cursor in a single SQLite database
        next to the session file, so a process restart resumes mid-chat
        instead of forcing a fresh X3DH (or a re-pair) on every peer. When
        no session_path is configured (in-memory client, e.g. tests) we
        fall back to volatile stores and a no-op ``atomic``.
        """
        from pywhats.appstate import InMemoryAppStateKeyStore
        from pywhats.appstate.store import InMemoryAppStateStore
        from pywhats.signal.experimental import (
            InMemoryIdentityStore,
            InMemoryLidMap,
            InMemoryPreKeyStore,
            InMemorySessionStore,
            SqliteStore,
        )
        from pywhats.signal.experimental.sender_key import InMemorySenderKeyStore

        if self._session_path:
            store = SqliteStore(f"{self._session_path}.signal.db")
            self._signal_store = store
            return (
                store.sessions,
                store.identities,
                store.lid_map,
                store.prekeys,
                store.app_state_keys,
                store.app_state,
                store.sender_keys,
                store.transaction,
            )
        return (
            InMemorySessionStore(),
            InMemoryIdentityStore(),
            InMemoryLidMap(),
            InMemoryPreKeyStore(),
            InMemoryAppStateKeyStore(),
            InMemoryAppStateStore(),
            InMemorySenderKeyStore(),
            None,
        )

    def _build_activator(
        self, *, transport: Any, iq_map: Any, device: DeviceStore, upload_prekeys: Any
    ) -> Any:  # pragma: no cover - integration
        """Build the post-``<success>`` activator with its persistence hook."""
        from pywhats.messaging.activator import SessionActivator, SuccessState

        async def _persist_success_state(state: SuccessState) -> None:
            if state.lid is not None:
                device.lid = state.lid
            self._save_device()

        return SessionActivator(
            transport=transport,
            iq_map=iq_map,
            push_name=device.push_name,
            on_state=_persist_success_state,
            on_fatal=self._on_keepalive_fatal,
            upload_prekeys=upload_prekeys,
        )

    def _on_keepalive_fatal(self, reason: str) -> None:
        """Called by the activator when app-level keepalive gives up.

        Closes the underlying socket so the receiver's ``recv`` raises and
        the normal teardown path runs exactly once (emitting a single
        ``disconnected``). Runs from inside the ping-loop task, so we
        schedule the close on the loop rather than awaiting here.
        """
        log.warning("client: %s; closing connection", reason)
        sock = self._sock
        if sock is None:
            return
        if self._fatal_task is not None and not self._fatal_task.done():
            return
        self._fatal_task = asyncio.create_task(sock.disconnect(), name="pywhats-fatal-close")

    async def _run_background_tasks(self) -> None:  # pragma: no cover - integration
        """Supervise the reader (and any future bg tasks) as a group."""
        if self._receiver is None:
            return
        reason = "receiver stopped"
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._receiver.run(), name="pywhats-receiver")
        except* Exception as exc_group:  # noqa: SIM117
            reason = f"background task group failed: {exc_group.exceptions}"
            log.error("client: %s", reason)
        finally:
            # Always tear the session down after the group exits.
            self._connected = False
            self._closed.set()
            log.info("client: session closed (%s); emitting disconnected", reason)
            await self._emit("disconnected")

    async def send_group_text(self, group: JID, text: str, participants: list[JID]) -> Message:
        """Send a text message to a group, fanning out the sender key (#39).

        ``participants`` is the group member list (the SKDM is distributed
        to each member's devices). Requires an active connection. Mirrors
        the whatsmeow sendGroup flow.
        """
        if not self._connected:
            raise NotConnected("call connect() first")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")
        return await sender.send_group_text(group, text, participants)  # type: ignore[no-any-return]

    async def get_group_info(self, group: JID) -> Any:
        """Fetch group metadata + participant list via a ``w:g2`` iq (#39)."""
        if not self._connected or self._send_iq is None:
            raise NotConnected("call connect() first")
        from pywhats.messaging.group import build_group_info_iq, parse_group_info
        from pywhats.messaging.ids import new_message_id

        resp = await self._send_iq(build_group_info_iq(group, new_message_id()))
        return parse_group_info(resp)

    async def send_image(
        self,
        chat: JID,
        image_bytes: bytes,
        *,
        mimetype: str = "image/jpeg",
        caption: str = "",
        width: int = 0,
        height: int = 0,
    ) -> Message:
        """Upload an image and send it as an ``ImageMessage`` to ``chat`` (#36).

        Encrypts + uploads the bytes to the media CDN, then sends a
        message referencing the resulting url / direct_path / media key.
        Requires an active connection. Mirrors the whatsmeow Upload ->
        ImageMessage -> SendMessage flow (upload.go).
        """
        if not self._connected or self._media_uploader is None:
            raise NotConnected("call connect() before send_image")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.media.crypto import MEDIA_IMAGE
        from pywhats.proto import Message as MessageProto

        upload = await self._media_uploader.upload(image_bytes, MEDIA_IMAGE)
        proto = MessageProto()
        img = proto.image_message
        img.url = upload.url
        img.direct_path = upload.direct_path
        img.media_key = upload.media_key
        img.file_enc_sha256 = upload.file_enc_sha256
        img.file_sha256 = upload.file_sha256
        img.file_length = upload.file_length
        img.mimetype = mimetype
        if caption:
            img.caption = caption
        if width:
            img.width = width
        if height:
            img.height = height
        return await sender.send_message(chat, proto, text=caption)  # type: ignore[no-any-return]

    async def send_video(
        self,
        chat: JID,
        video_bytes: bytes,
        *,
        mimetype: str = "video/mp4",
        caption: str = "",
    ) -> Message:
        """Upload a video and send it as a ``VideoMessage`` to ``chat``.

        Same pipeline as :meth:`send_image`: encrypt + upload to the
        media CDN, then send a message referencing the upload.
        """
        if not self._connected or self._media_uploader is None:
            raise NotConnected("call connect() before send_video")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.media.crypto import MEDIA_VIDEO
        from pywhats.proto import Message as MessageProto

        upload = await self._media_uploader.upload(video_bytes, MEDIA_VIDEO)
        proto = MessageProto()
        vid = proto.video_message
        vid.url = upload.url
        vid.direct_path = upload.direct_path
        vid.media_key = upload.media_key
        vid.file_enc_sha256 = upload.file_enc_sha256
        vid.file_sha256 = upload.file_sha256
        vid.file_length = upload.file_length
        vid.mimetype = mimetype
        if caption:
            vid.caption = caption
        return await sender.send_message(chat, proto, text=caption)  # type: ignore[no-any-return]

    async def edit_message(
        self,
        chat: JID,
        message_id: str,
        new_text: str,
        *,
        from_me: bool = True,
    ) -> Message:
        """Edit an earlier text message in ``chat`` (whatsmeow ``BuildEdit``).

        ``message_id`` + ``from_me`` address the message being edited
        (edits are normally of our own messages, so ``from_me`` defaults
        to True). Ships a ProtocolMessage{type=MESSAGE_EDIT, key,
        edited_message} with the outer stanza ``edit="1"`` attribute.
        """
        return await self._send_protocol_edit(
            chat, message_id, from_me, new_text=new_text, revoke=False
        )

    async def revoke_message(
        self,
        chat: JID,
        message_id: str,
        *,
        from_me: bool = True,
    ) -> Message:
        """Delete (revoke) an earlier message for everyone (whatsmeow ``BuildRevoke``).

        Ships a ProtocolMessage{type=REVOKE, key} with the outer stanza
        ``edit="7"`` attribute.
        """
        return await self._send_protocol_edit(chat, message_id, from_me, new_text=None, revoke=True)

    async def _send_protocol_edit(
        self,
        chat: JID,
        message_id: str,
        from_me: bool,
        *,
        new_text: str | None,
        revoke: bool,
    ) -> Message:
        if not self._connected:
            raise NotConnected("call connect() first")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.proto import Message as MessageProto
        from pywhats.proto import ProtocolMessage

        proto = MessageProto()
        pm = proto.protocol_message
        pm.key.remote_jid = f"{chat.user}@{chat.server}"
        pm.key.from_me = from_me
        pm.key.id = message_id
        if revoke:
            pm.type = ProtocolMessage.REVOKE
            edit_attr = "7"  # EditAttributeSenderRevoke (public writeups)
        else:
            pm.type = ProtocolMessage.MESSAGE_EDIT
            pm.edited_message.conversation = new_text or ""
            edit_attr = "1"  # EditAttributeMessageEdit (public writeups)
        return await sender.send_message(  # type: ignore[no-any-return]
            chat, proto, edit=edit_attr
        )

    async def send_reaction(
        self,
        chat: JID,
        message_id: str,
        emoji: str,
        *,
        from_me: bool = False,
    ) -> Message:
        """React to an existing message in ``chat`` (empty ``emoji`` removes).

        ``message_id`` + ``from_me`` address the reacted-to message:
        ``from_me=True`` when reacting to a message we sent ourselves.
        Mirrors whatsmeow ``BuildReaction``.
        """
        import time

        if not self._connected:
            raise NotConnected("call connect() first")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.proto import Message as MessageProto

        proto = MessageProto()
        rm = proto.reaction_message
        rm.key.remote_jid = f"{chat.user}@{chat.server}"
        rm.key.from_me = from_me
        rm.key.id = message_id
        # Always set text (present-but-empty for a removal), matching
        # whatsmeow BuildReaction — a recipient distinguishes "remove
        # reaction" by a present empty string, not an absent field.
        rm.text = emoji
        rm.sender_timestamp_ms = int(time.time() * 1000)
        return await sender.send_message(  # type: ignore[no-any-return]
            chat, proto, message_type="reaction"
        )

    async def send_sticker(
        self,
        chat: JID,
        sticker_bytes: bytes,
        *,
        mimetype: str = "image/webp",
    ) -> Message:
        """Upload a webp sticker and send it as a ``StickerMessage`` to ``chat``.

        Stickers are encrypted under the *Image* media keys and uploaded
        to the image CDN endpoint (see proto/e2e.proto). Same pipeline
        as :meth:`send_image`.
        """
        if not self._connected or self._media_uploader is None:
            raise NotConnected("call connect() before send_sticker")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.media.crypto import MEDIA_IMAGE
        from pywhats.proto import Message as MessageProto

        upload = await self._media_uploader.upload(sticker_bytes, MEDIA_IMAGE)
        proto = MessageProto()
        stk = proto.sticker_message
        stk.url = upload.url
        stk.direct_path = upload.direct_path
        stk.media_key = upload.media_key
        stk.file_enc_sha256 = upload.file_enc_sha256
        stk.file_sha256 = upload.file_sha256
        stk.file_length = upload.file_length
        stk.mimetype = mimetype
        return await sender.send_message(chat, proto)  # type: ignore[no-any-return]

    async def send_audio(
        self,
        chat: JID,
        audio_bytes: bytes,
        *,
        mimetype: str = "audio/ogg; codecs=opus",
        ptt: bool = False,
    ) -> Message:
        """Upload audio and send it as an ``AudioMessage`` to ``chat``.

        ``ptt=True`` marks a voice note (push-to-talk), rendered with
        the play/waveform UI. Same pipeline as :meth:`send_image`.
        """
        if not self._connected or self._media_uploader is None:
            raise NotConnected("call connect() before send_audio")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.media.crypto import MEDIA_AUDIO
        from pywhats.proto import Message as MessageProto

        upload = await self._media_uploader.upload(audio_bytes, MEDIA_AUDIO)
        proto = MessageProto()
        aud = proto.audio_message
        aud.url = upload.url
        aud.direct_path = upload.direct_path
        aud.media_key = upload.media_key
        aud.file_enc_sha256 = upload.file_enc_sha256
        aud.file_sha256 = upload.file_sha256
        aud.file_length = upload.file_length
        aud.mimetype = mimetype
        if ptt:
            aud.ptt = True
        return await sender.send_message(chat, proto)  # type: ignore[no-any-return]

    async def send_document(
        self,
        chat: JID,
        document_bytes: bytes,
        *,
        mimetype: str = "application/octet-stream",
        filename: str = "",
        caption: str = "",
    ) -> Message:
        """Upload a document and send it as a ``DocumentMessage`` to ``chat``.

        Same pipeline as :meth:`send_image`: encrypt + upload to the
        media CDN, then send a message referencing the upload.
        """
        if not self._connected or self._media_uploader is None:
            raise NotConnected("call connect() before send_document")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")

        from pywhats.media.crypto import MEDIA_DOCUMENT
        from pywhats.proto import Message as MessageProto

        upload = await self._media_uploader.upload(document_bytes, MEDIA_DOCUMENT)
        proto = MessageProto()
        doc = proto.document_message
        doc.url = upload.url
        doc.direct_path = upload.direct_path
        doc.media_key = upload.media_key
        doc.file_enc_sha256 = upload.file_enc_sha256
        doc.file_sha256 = upload.file_sha256
        doc.file_length = upload.file_length
        doc.mimetype = mimetype
        if filename:
            doc.file_name = filename
        if caption:
            doc.caption = caption
        return await sender.send_message(chat, proto, text=caption)  # type: ignore[no-any-return]

    async def download_media(self, info: Any) -> bytes:
        """Download and decrypt an attachment described by a ``MediaInfo`` (#36).

        ``info`` carries the message's ``direct_path``, 32-byte
        ``media_key``, the two integrity hashes, and the media type. Returns
        the decrypted bytes. Requires an active connection.
        """
        if not self._connected or self._media_downloader is None:
            raise NotConnected("call connect() before download_media")
        return await self._media_downloader.download(info)  # type: ignore[no-any-return]

    async def _emit_app_state_events(self, name: str, mutations: list[Any]) -> None:
        """Turn decoded app-state mutations into typed events (#35d).

        Each mute/pin/archive/contact/pushname SET mutation is emitted
        under its own event name (``mute``, ``pin``, ``archive``,
        ``contact``, ``pushname``); other mutations are ignored here.
        """
        from pywhats.appstate.events import app_state_mutation_to_event

        for mutation in mutations:
            mapped = app_state_mutation_to_event(mutation)
            if mapped is not None:
                event_name, payload = mapped
                await self._emit(event_name, payload)

    async def send_text(self, chat: JID, text: str, *, reply_to: Any = None) -> Message:
        """Encrypt and send a text message to ``chat``.

        Requires :meth:`connect` to have been called first and a
        :class:`pywhats.messaging.Sender` to have been attached via
        :meth:`_install_sender` during the connect path.

        ``reply_to`` quotes an earlier message: pass the inbound
        :class:`pywhats.events.Message` (or a ``MessageKey`` proto) being
        replied to and the reply carries its quote metadata.
        """
        if not self._connected:
            raise NotConnected("call connect() first")
        sender = getattr(self, "_sender", None)
        if sender is None:
            raise NotConnected("message sender is not wired up")
        return await sender.send_text(chat, text, reply_to=reply_to)  # type: ignore[no-any-return]

    async def mark_read(
        self, chat: JID, message_ids: list[str], *, sender: JID | None = None
    ) -> None:
        """Send a ``receipt type="read"`` (blue ticks) for displayed messages.

        ``sender`` is the original message author, required only for group
        chats (whatsmeow ``MarkRead``). Requires an active connection.
        """
        import time

        from pywhats.messaging.presence import build_read_receipt

        node = build_read_receipt(chat, message_ids, sender=sender, timestamp=int(time.time()))
        await self._send_stanza(node, "mark_read")

    async def send_presence(self, state: str) -> None:
        """Announce global presence (``available`` / ``unavailable``).

        Carries the account push name so peers see the display name
        (whatsmeow ``SendPresence``).
        """
        from pywhats.messaging.presence import build_presence

        name = self._device.push_name if self._device is not None else None
        await self._send_stanza(build_presence(state, name=name), "send_presence")

    async def subscribe_presence(self, jid: JID) -> None:
        """Subscribe to a peer's presence updates (whatsmeow ``SubscribePresence``).

        Presence stanzas then arrive as ``presence`` events. Mark yourself
        ``available`` first, as the server only relays presence to online
        clients.
        """
        from pywhats.messaging.presence import build_subscribe_presence

        await self._send_stanza(build_subscribe_presence(jid), "subscribe_presence")

    async def send_chat_presence(self, jid: JID, state: str, *, media: str | None = None) -> None:
        """Send a typing/recording update (``composing`` / ``paused``).

        ``media="audio"`` on ``composing`` marks recording (whatsmeow
        ``SendChatPresence``).
        """
        if self._device is None:
            raise NotConnected("no device credentials")
        from pywhats.messaging.presence import build_chat_presence

        own = _own_signal_jid(self._device)
        await self._send_stanza(build_chat_presence(own, jid, state, media=media), "chat_presence")

    async def _send_stanza(self, node: Any, what: str) -> None:
        from pywhats.binary import encode

        if not self._connected or self._transport is None:
            raise NotConnected(f"call connect() before {what}")
        await self._transport.send(encode(node))

    def _install_sender(self, sender: Any) -> None:
        """Attach a pre-built :class:`pywhats.messaging.Sender` instance.

        The actual wiring happens in the connect path once #10 lands
        the frame-reader. For now this hook lets callers (and tests)
        bolt a sender on directly.
        """
        self._sender = sender

    async def disconnect(self) -> None:
        """Close the connection cleanly.

        Cancels the background task group (reader + any other bg
        workers), closes the underlying socket, and emits
        ``disconnected``. Idempotent.
        """
        already = not self._connected and self._bg_task is None and self._sock is None
        self._connected = False
        bg = self._bg_task
        self._bg_task = None
        if bg is not None and not bg.done():
            bg.cancel()
            try:
                await bg
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        activator = self._activator
        self._activator = None
        if activator is not None:
            try:
                await activator.stop()
            except Exception:  # noqa: BLE001
                log.exception("error stopping activator")
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                await sock.disconnect()
            except Exception:  # noqa: BLE001
                log.exception("error during socket disconnect")
        self._transport = None
        self._receiver = None
        store = self._signal_store
        self._signal_store = None
        if store is not None:
            try:
                store.close()
            except Exception:  # noqa: BLE001
                log.exception("error closing signal store")
        self._closed.set()
        if not already:
            await self._emit("disconnected")

    async def wait_closed(self) -> None:
        """Block until the client disconnects."""
        await self._closed.wait()


def _make_responder_identity(device: DeviceStore, prekey_store: Any) -> Any:  # pragma: no cover
    """Adapt the device credentials + prekey store to ``ResponderIdentityProvider``."""

    class _Identity:
        @property
        def identity_private(self) -> bytes:
            return device.identity_private

        @property
        def identity_public(self) -> bytes:
            return device.identity_public

        @property
        def registration_id(self) -> int:
            return device.registration_id

        def get_signed_pre_key(self, key_id: int) -> Any:
            # Only the currently-advertised SPK is known in phase 1.
            if key_id != device.signed_pre_key_id:
                raise ValueError(f"unknown signed pre-key id {key_id}")
            return device.signed_pre_key()

        def get_one_time_pre_key(self, key_id: int) -> Any:
            # Look up the private half of a previously-uploaded OPK so
            # a peer's first pkmsg that references it can complete X3DH.
            return prekey_store.load(key_id)

        def consume_one_time_pre_key(self, key_id: int) -> None:
            # An OPK is single-use: drop it once a session consumes it.
            prekey_store.delete(key_id)

    return _Identity()


def _own_signal_jid(device: DeviceStore) -> JID:  # pragma: no cover
    if device.jid is None:
        return JID(user="", server="s.whatsapp.net")
    return JID(user=device.jid.user, server=device.jid.server, device=device.jid.device)


def _log_unpersisted_routing_info(data: bytes) -> None:  # pragma: no cover
    # Routing info will eventually be appended as ``ED=<base64url>``
    # on the next WSS connect URL. For now we just log it; the
    # DeviceStore dataclass is slotted, so adding a field to it
    # is a separate change.
    log.debug("ignoring edge_routing routing_info (%d bytes); not yet persisted", len(data))
