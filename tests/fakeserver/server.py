# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""In-process fake WhatsApp server for offline integration tests.

The real client connects to this over a genuine local websocket. The
server speaks the real Noise XX handshake (responder side, see
:mod:`tests.fakeserver.noise`) and the real binary-node framing, reusing
the client's own ``pywhats`` modules throughout — it is a test double,
never a second protocol implementation.

Scriptable scenarios (see the goal spec):

    a. full handshake + login resume from stored creds
    b. deliver an inbound encrypted text message
    c. accept an outbound send_text and assert its wire shape
    d. go silent (stop answering pings) to exercise the keep-alive path
    e. half-close / EOF the socket mid-session

Usage::

    async with FakeWhatsAppServer(client_device=device) as server:
        client = Client(...)   # pointed at server.url
        await client.connect()
        await server.handshake_complete.wait()
        await server.deliver_text(peer, "hi")
        ...
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

import websockets
from websockets.asyncio.server import Server, ServerConnection, serve

from pywhats.binary import Node, decode, encode
from pywhats.events import JID
from pywhats.messaging.padding import pad_random_max16
from pywhats.proto import ClientPayload
from pywhats.proto import Message as MessageProto
from pywhats.signal.experimental import (
    IdentityKeyPair,
    PreKeyBundle,
    SignalMessage,
    SignedPreKey,
    ratchet_encrypt,
    ratchet_init_alice,
    x3dh_initiator,
)
from pywhats.signal.experimental.types import PreKeySignalMessage
from pywhats.socket.crypto import generate_keypair

from .noise import ServerHandshake

_log = logging.getLogger("tests.fakeserver")

_SERVER_JID = JID(user="", server="s.whatsapp.net")


# --- framed channel over a server websocket --------------------------


class _WSFrameChannel:
    """3-byte length framing over a websockets ServerConnection.

    The client sends exactly one framed payload per websocket message
    (its ``send_frame`` does one ``ws.send`` per frame), and prefixes the
    very first frame with the 4-byte ``WA\\x06\\x03`` intro header.
    """

    def __init__(self, ws: ServerConnection) -> None:
        self._ws = ws
        self._first = True

    async def recv_frame(self) -> bytes:
        msg = await self._ws.recv()
        data = msg if isinstance(msg, bytes) else msg.encode("utf-8")
        if self._first:
            self._first = False
            if data[:4] == b"WA\x06\x03":
                data = data[4:]
        n = int.from_bytes(data[:3], "big")
        return data[3 : 3 + n]

    async def send_frame(self, payload: bytes) -> None:
        await self._ws.send(len(payload).to_bytes(3, "big") + payload)


# --- server-side Signal peer -----------------------------------------


@dataclass
class SignalPeer:
    """A server-side Signal identity used to encrypt inbound messages and
    answer prekey queries, reusing the client's own Signal primitives."""

    jid: JID
    registration_id: int = 5555
    signed_pre_key_id: int = 1
    identity: IdentityKeyPair = field(default_factory=IdentityKeyPair.generate)
    _spk: SignedPreKey = field(init=False)
    _ratchet: object | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._spk = SignedPreKey.generate(self.identity, self.signed_pre_key_id)

    def prekey_bundle_node(self, iq_id: str) -> Node:
        """Build the ``<iq xmlns=encrypt>`` result the client fetches."""
        user = Node(
            tag="user",
            attrs={"jid": self.jid},
            content=[
                Node(tag="registration", content=self.registration_id.to_bytes(4, "big")),
                Node(tag="identity", content=self.identity.public),
                Node(
                    tag="skey",
                    content=[
                        Node(tag="id", content=self.signed_pre_key_id.to_bytes(3, "big")),
                        Node(tag="value", content=self._spk.public),
                        Node(tag="signature", content=self._spk.signature),
                    ],
                ),
            ],
        )
        return Node(
            tag="iq",
            attrs={"id": iq_id, "type": "result", "from": _SERVER_JID},
            content=[Node(tag="list", content=[user])],
        )

    def encrypt_text_to(
        self, *, client_identity_public: bytes, client_bundle: PreKeyBundle, text: str
    ) -> bytes:
        return self.encrypt_proto_to(
            client_identity_public=client_identity_public,
            client_bundle=client_bundle,
            proto=MessageProto(conversation=text),
        )

    def encrypt_proto_to(
        self, *, client_identity_public: bytes, client_bundle: PreKeyBundle, proto: MessageProto
    ) -> bytes:
        """Return the ``pkmsg`` ciphertext bytes for a first inbound Message proto.

        Runs X3DH as the initiator against the *client's* published bundle
        so the client's receiver can rebuild the same shared secret.
        """
        result = x3dh_initiator(self.identity, client_bundle)
        state = ratchet_init_alice(result.shared_secret, client_bundle.signed_pre_key_public)
        self._ratchet = state
        plaintext = pad_random_max16(proto.SerializeToString())
        ad = self.identity.public + client_identity_public
        header, ciphertext, mac_key = ratchet_encrypt(state, plaintext, ad)
        signal = SignalMessage(header=header, ciphertext=ciphertext)
        pkmsg = PreKeySignalMessage(
            # Reference the OPK the X3DH actually consumed (if any), so the
            # responder recomputes the matching shared secret.
            registration_id=self.registration_id,
            one_time_pre_key_id=result.used_one_time_pre_key_id,
            signed_pre_key_id=client_bundle.signed_pre_key_id,
            base_key=result.ephemeral_public,
            identity_key=self.identity.public,
            message=signal,
        )
        return pkmsg.encode(self.identity.public, client_identity_public, mac_key)

    def decrypt_pkmsg(self, ciphertext: bytes, *, client_identity_public: bytes) -> bytes:
        """Responder-side decrypt of an inbound ``pkmsg`` from the client.

        Runs X3DH as the responder against our signed prekey so a test can
        recover the plaintext the client encrypted to us (e.g. the group
        SenderKeyDistributionMessage in a group-send fan-out).
        """
        from pywhats.messaging.padding import unpad_random_max16
        from pywhats.signal.experimental import ratchet_decrypt, ratchet_init_bob, x3dh_responder
        from pywhats.signal.experimental.keys import IdentityKeyPair as _IKP

        pkmsg = PreKeySignalMessage.decode(ciphertext)
        identity = _IKP(private=self.identity.private, public=self.identity.public)
        result = x3dh_responder(identity, self._spk, None, pkmsg.identity_key, pkmsg.base_key)
        state = ratchet_init_bob(result.shared_secret, self._spk.private, self._spk.public)
        ad = pkmsg.identity_key + self.identity.public
        plaintext = ratchet_decrypt(
            state,
            pkmsg.message.header,
            pkmsg.message.ciphertext,
            ad,
            verify_mac=lambda mac_key: pkmsg.message.verify_mac(
                pkmsg.identity_key, self.identity.public, mac_key
            ),
        )
        return unpad_random_max16(plaintext)

    def encrypt_followup_text(self, *, client_identity_public: bytes, text: str) -> bytes:
        """Return a plain ``msg`` ciphertext on the already-established ratchet.

        Used to prove a persisted session resumes: the receiver must load
        the session from storage (no pkmsg to re-establish it).
        """
        if self._ratchet is None:
            raise RuntimeError("no ratchet yet — call encrypt_text_to first")
        plaintext = pad_random_max16(MessageProto(conversation=text).SerializeToString())
        ad = self.identity.public + client_identity_public
        header, ciphertext, mac_key = ratchet_encrypt(self._ratchet, plaintext, ad)  # type: ignore[arg-type]
        signal = SignalMessage(header=header, ciphertext=ciphertext)
        return signal.encode(self.identity.public, client_identity_public, mac_key)


# --- the server ------------------------------------------------------


class FakeWhatsAppServer:
    """Offline fake WhatsApp edge. Async context manager."""

    def __init__(
        self,
        *,
        answer_pings: bool = True,
        send_success: bool = True,
        success_lid: str | None = "111111111111111.0:1@lid",
        peer: SignalPeer | None = None,
        initial_prekey_count: int = 0,
    ) -> None:
        self.answer_pings = answer_pings
        self.send_success = send_success
        self.success_lid = success_lid
        self.peer = peer
        # Server-side view of how many of the client's OPKs remain; count
        # queries report it and uploads add to it (whatsmeow prekeys.go).
        self.server_prekey_count = initial_prekey_count
        # collection name -> serialized SyncdPatch bytes returned for a
        # w:sync:app:state fetch of that collection (issue #35c).
        self.app_state_patches: dict[str, list[bytes]] = {}
        self.app_state_fetches: list[Node] = []

        self._server: Server | None = None
        self._port = 0
        self._transport: object | None = None
        self._conn: ServerConnection | None = None
        self._outbound: asyncio.Queue[Node] = asyncio.Queue()
        self._tasks: list[asyncio.Task[None]] = []

        # Observable state for assertions.
        self.received: list[Node] = []
        self.prekey_uploads: list[Node] = []
        self.prekey_count_queries: list[Node] = []
        self.client_payload: ClientPayload | None = None
        self.mode: str | None = None  # "login" | "register"
        self.handshake_complete = asyncio.Event()
        self.connection_closed = asyncio.Event()
        self.ping_count = 0

    # ---- lifecycle --------------------------------------------------

    async def __aenter__(self) -> FakeWhatsAppServer:
        self._server = await serve(self._handle, "127.0.0.1", 0)
        self._port = next(iter(self._server.sockets)).getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        for t in self._tasks:
            if not t.done():
                t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        if self._conn is not None:
            with contextlib.suppress(Exception):
                await self._conn.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self._port}"

    # ---- test-facing controls --------------------------------------

    async def deliver(self, node: Node) -> None:
        """Queue a stanza to be noise-encrypted and sent to the client."""
        await self._outbound.put(node)

    async def deliver_text(
        self,
        peer: SignalPeer,
        text: str,
        *,
        client_device: object,
        opk_id: int | None = None,
        opk_public: bytes | None = None,
    ) -> str:
        """Encrypt ``text`` from ``peer`` and deliver it as a ``<message>``."""
        return await self.deliver_proto(
            peer,
            MessageProto(conversation=text),
            client_device=client_device,
            opk_id=opk_id,
            opk_public=opk_public,
        )

    async def deliver_proto(
        self,
        peer: SignalPeer,
        proto: MessageProto,
        *,
        client_device: object,
        opk_id: int | None = None,
        opk_public: bytes | None = None,
    ) -> str:
        """Encrypt a ``Message`` proto from ``peer`` and deliver it as a ``<message>``.

        ``client_device`` is the client's DeviceStore, used to build the
        client's published prekey bundle so the pkmsg decrypts. When
        ``opk_id``/``opk_public`` are given, the pkmsg references that
        one-time prekey (proving the client's uploaded OPK is consumable).
        """
        client_bundle = PreKeyBundle(
            identity_key=client_device.identity_public,  # type: ignore[attr-defined]
            signed_pre_key_id=client_device.signed_pre_key_id,  # type: ignore[attr-defined]
            signed_pre_key_public=client_device.signed_pre_key_public,  # type: ignore[attr-defined]
            signed_pre_key_signature=client_device.signed_pre_key_signature,  # type: ignore[attr-defined]
            one_time_pre_key_id=opk_id,
            one_time_pre_key_public=opk_public,
        )
        ciphertext = peer.encrypt_proto_to(
            client_identity_public=client_device.identity_public,  # type: ignore[attr-defined]
            client_bundle=client_bundle,
            proto=proto,
        )
        msg_id = f"inbound-{int(time.time() * 1000) % 100000}"
        node = Node(
            tag="message",
            attrs={"id": msg_id, "from": peer.jid, "type": "text", "t": str(int(time.time()))},
            content=[Node(tag="enc", attrs={"v": "2", "type": "pkmsg"}, content=ciphertext)],
        )
        await self.deliver(node)
        return msg_id

    async def deliver_followup_text(
        self,
        peer: SignalPeer,
        text: str,
        *,
        client_device: object,
        from_jid: JID | None = None,
        extra_attrs: dict[str, str | int | JID] | None = None,
    ) -> str:
        """Deliver a follow-up ``<message>`` (enc type ``msg``) on the live session.

        ``from_jid`` overrides the stanza ``from`` (e.g. address the message
        from the peer's LID). ``extra_attrs`` adds stanza attributes such as
        ``sender_pn`` so the client can map PN<->LID.
        """
        ciphertext = peer.encrypt_followup_text(
            client_identity_public=client_device.identity_public,  # type: ignore[attr-defined]
            text=text,
        )
        msg_id = f"followup-{int(time.time() * 1000) % 100000}"
        attrs: dict[str, str | int | JID] = {
            "id": msg_id,
            "from": from_jid if from_jid is not None else peer.jid,
            "type": "text",
            "t": str(int(time.time())),
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        node = Node(
            tag="message",
            attrs=attrs,
            content=[Node(tag="enc", attrs={"v": "2", "type": "msg"}, content=ciphertext)],
        )
        await self.deliver(node)
        return msg_id

    async def deliver_server_sync(self, collections: list[tuple[str, int]]) -> None:
        """Push a ``<notification type="server_sync">`` advertising updated collections.

        Mirrors the live push shape (design spec §): one ``<collection
        name= version=>`` child per updated app-state collection.
        """
        children = [
            Node(tag="collection", attrs={"name": name, "version": str(version)})
            for name, version in collections
        ]
        await self.deliver(
            Node(
                tag="notification",
                attrs={"from": _SERVER_JID, "type": "server_sync", "id": "srv-sync-1"},
                content=children,
            )
        )

    async def deliver_failure(self, reason: str = "401", location: str = "rva") -> None:
        """Send a server ``<failure>`` login-rejection stanza to the client."""
        await self.deliver(Node(tag="failure", attrs={"reason": reason, "location": location}))

    async def close_connection(self) -> None:
        """Half-close / EOF the live websocket (scenario e)."""
        if self._conn is not None:
            await self._conn.close()

    async def send(self, node: Node) -> None:
        """Directly noise-encrypt and send a stanza (bypassing the queue)."""
        transport = self._transport
        assert transport is not None
        await transport.send(encode(node))  # type: ignore[attr-defined]

    # ---- connection handler ----------------------------------------

    async def _handle(self, ws: ServerConnection) -> None:
        self._conn = ws
        # Fresh outbound queue per connection so a stale writer from a
        # previous connection can never steal this client's stanzas.
        self._outbound = asyncio.Queue()
        channel = _WSFrameChannel(ws)
        static_priv, _ = generate_keypair()
        handshake = ServerHandshake(channel, server_static_private=static_priv)
        try:
            transport, client_payload_bytes = await handshake.perform()
        except Exception:
            _log.exception("fakeserver: handshake failed")
            return
        self._transport = transport
        cp = ClientPayload()
        cp.ParseFromString(client_payload_bytes)
        self.client_payload = cp
        self.mode = "register" if cp.HasField("device_pairing_data") else "login"
        _log.info("fakeserver: handshake complete, mode=%s", self.mode)
        self.handshake_complete.set()

        if self.send_success and self.mode == "login":
            await self._send_success()

        writer = asyncio.create_task(self._writer_loop(self._outbound, transport))
        self._tasks.append(writer)
        try:
            await self._reader_loop(transport)
        finally:
            self.connection_closed.set()

    async def _send_success(self) -> None:
        attrs: dict[str, str | int | JID] = {"t": str(int(time.time()))}
        if self.success_lid is not None:
            attrs["lid"] = self.success_lid
        await self.send(Node(tag="success", attrs=attrs))

    async def _writer_loop(self, queue: asyncio.Queue[Node], transport: object) -> None:
        while True:
            node = await queue.get()
            await transport.send(encode(node))  # type: ignore[attr-defined]

    async def _reader_loop(self, transport: object) -> None:
        while True:
            try:
                frame = await transport.recv()  # type: ignore[attr-defined]
            except Exception:
                _log.info("fakeserver: client connection closed")
                return
            try:
                node = decode(frame)
            except Exception:
                _log.warning("fakeserver: undecodable client frame")
                continue
            self.received.append(node)
            await self._dispatch(node)

    async def _dispatch(self, node: Node) -> None:
        tag = node.tag
        if tag == "iq":
            await self._handle_iq(node)
        elif tag == "message":
            await self._ack_message(node)
        # presence / ib / receipt: recorded only.

    async def _handle_iq(self, node: Node) -> None:
        iq_id = node.get_str("id")
        # A result/error is a reply to something WE sent (e.g. the client
        # answering our server-initiated ping) — never reply to it.
        if node.get_str("type") in ("result", "error"):
            return
        xmlns = node.get_str("xmlns")
        if xmlns == "w:p":
            self.ping_count += 1
            if self.answer_pings:
                await self.send(self._iq_result(iq_id))
            return
        if xmlns == "encrypt":
            # type="get" with <count/> is the OPK-count query (whatsmeow
            # getServerPreKeyCount); other gets are prekey-bundle fetches;
            # type="set" is our OPK upload (whatsmeow uploadPreKeys).
            if node.get_str("type") == "get" and node.get_child("count") is not None:
                self.prekey_count_queries.append(node)
                result = Node(
                    tag="iq",
                    attrs={"id": iq_id, "type": "result", "from": _SERVER_JID},
                    content=[Node(tag="count", attrs={"value": str(self.server_prekey_count)})],
                )
                await self.send(result)
            elif node.get_str("type") == "get" and self.peer is not None:
                await self.send(self.peer.prekey_bundle_node(iq_id))
            else:
                self.prekey_uploads.append(node)
                lst = node.get_child("list")
                if lst is not None:
                    self.server_prekey_count += len(lst.get_children("key"))
                await self.send(self._iq_result(iq_id))
            return
        if xmlns == "usync" and self.peer is not None:
            await self.send(self._usync_result(iq_id))
            return
        if xmlns == "w:sync:app:state":
            await self.send(self._app_state_result(node))
            return
        if xmlns == "w:m":
            await self.send(self._media_conn_result(iq_id))
            return
        # passive/active and anything else: bare result.
        await self.send(self._iq_result(iq_id))

    def _media_conn_result(self, iq_id: str) -> Node:
        """Answer a ``w:m`` media-conn query with a single dummy host.

        The host never has to work — media download/upload HTTP is injected
        in tests — but the client needs a well-formed ``<media_conn>`` to
        build a URL.
        """
        mc = Node(
            tag="media_conn",
            attrs={"auth": "TESTAUTH", "ttl": "3600"},
            content=[Node(tag="host", attrs={"hostname": "mmg.test"})],
        )
        return Node(
            tag="iq",
            attrs={"id": iq_id, "type": "result", "from": _SERVER_JID},
            content=[mc],
        )

    def _app_state_result(self, node: Node) -> Node:
        """Answer a ``w:sync:app:state`` fetch with any queued patches.

        Returns ``<iq result><sync><collection name=><patches><patch>bytes
        </patch></patches></collection></sync></iq>`` — the inline patch
        shape whatsmeow parses in ``ParsePatchList``.
        """
        self.app_state_fetches.append(node)
        iq_id = node.get_str("id")
        sync = node.get_child("sync")
        req = sync.get_child("collection") if sync is not None else None
        name = req.get_str("name") if req is not None else ""
        patch_nodes = [
            Node(tag="patch", content=blob) for blob in self.app_state_patches.get(name, [])
        ]
        collection = Node(
            tag="collection",
            attrs={"name": name},
            content=[Node(tag="patches", content=patch_nodes)],
        )
        return Node(
            tag="iq",
            attrs={"id": iq_id, "type": "result", "from": _SERVER_JID},
            content=[Node(tag="sync", content=[collection])],
        )

    def _iq_result(self, iq_id: str) -> Node:
        return Node(tag="iq", attrs={"id": iq_id, "type": "result", "from": _SERVER_JID})

    def _usync_result(self, iq_id: str) -> Node:
        assert self.peer is not None
        user = Node(tag="user", attrs={"jid": self.peer.jid})
        usync = Node(tag="usync", content=[Node(tag="list", content=[user])])
        return Node(
            tag="iq",
            attrs={"id": iq_id, "type": "result", "from": _SERVER_JID},
            content=[usync],
        )

    async def _ack_message(self, node: Node) -> None:
        msg_id = node.get_str("id")
        await self.send(Node(tag="ack", attrs={"id": msg_id, "class": "message"}))


# Keep the websockets import referenced for type clarity in tests.
_ = websockets
