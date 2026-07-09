# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""0.2.0 media types e2e: send + receive documents (video/audio/sticker follow).

Inbound: a peer delivers a media message; the ``message`` event must
carry a :class:`pywhats.events.MediaAttachment` with enough info to
``Client.download_media`` the attachment (verified against a real
``encrypt_media`` blob served through an injected HTTP GET). Outbound:
``Client.send_document`` uploads through the media pipeline (injected
HTTP POST) and ships a ``DocumentMessage`` the peer can decrypt and
download.
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, Message
from pywhats.media.crypto import MEDIA_AUDIO, MEDIA_DOCUMENT, MEDIA_VIDEO, decrypt_media
from pywhats.media.upload import encrypt_media
from pywhats.proto import Message as MessageProto

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_MEDIA_KEY = b"\x21" * 32
_DOC_BYTES = b"%PDF-1.4 fake report body " * 40
_VIDEO_BYTES = b"\x00\x00\x00\x18ftypmp42 fake mp4 payload " * 50
_AUDIO_BYTES = b"OggS fake opus voice note " * 30


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _on_connected() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_inbound_document_surfaces_attachment_and_downloads() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    enc = encrypt_media(_DOC_BYTES, MEDIA_DOCUMENT, media_key=_MEDIA_KEY)

    async def _fake_get(url: str) -> bytes:
        assert "mms-type=document" in url
        return enc.enc_data

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_get=_fake_get)
        client._device = device

        received: list[Message] = []

        @client.on("message")
        async def _on_message(m: Message) -> None:
            received.append(m)

        await _connect(client, server)

        proto = MessageProto()
        doc = proto.document_message
        doc.direct_path = "/v/t62.7119-24/doc.enc"
        doc.media_key = enc.media_key
        doc.file_sha256 = enc.file_sha256
        doc.file_enc_sha256 = enc.file_enc_sha256
        doc.file_length = enc.file_length
        doc.mimetype = "application/pdf"
        doc.file_name = "report.pdf"
        doc.caption = "Q3 numbers"
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(received))
        msg = received[0]
        media = msg.media
        assert media is not None
        assert media.kind == "document"
        assert media.mimetype == "application/pdf"
        assert media.filename == "report.pdf"
        assert media.caption == "Q3 numbers"
        assert media.media_type == MEDIA_DOCUMENT
        assert media.file_length == len(_DOC_BYTES)

        plaintext = await client.download_media(media)
        assert plaintext == _DOC_BYTES

        await client.disconnect()


async def test_inbound_video_surfaces_attachment_and_downloads() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    enc = encrypt_media(_VIDEO_BYTES, MEDIA_VIDEO, media_key=_MEDIA_KEY)

    async def _fake_get(url: str) -> bytes:
        assert "mms-type=video" in url
        return enc.enc_data

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_get=_fake_get)
        client._device = device

        received: list[Message] = []

        @client.on("message")
        async def _on_message(m: Message) -> None:
            received.append(m)

        await _connect(client, server)

        proto = MessageProto()
        vid = proto.video_message
        vid.direct_path = "/v/t62.7161-24/vid.enc"
        vid.media_key = enc.media_key
        vid.file_sha256 = enc.file_sha256
        vid.file_enc_sha256 = enc.file_enc_sha256
        vid.file_length = enc.file_length
        vid.mimetype = "video/mp4"
        vid.caption = "clip"
        vid.seconds = 12
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(received))
        media = received[0].media
        assert media is not None
        assert media.kind == "video"
        assert media.mimetype == "video/mp4"
        assert media.caption == "clip"
        assert media.media_type == MEDIA_VIDEO
        assert media.file_length == len(_VIDEO_BYTES)

        plaintext = await client.download_media(media)
        assert plaintext == _VIDEO_BYTES

        await client.disconnect()


async def test_outbound_send_video_uploads_and_ships_video_message() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    posted: list[tuple[str, bytes]] = []

    async def _fake_post(url: str, body: bytes) -> bytes:
        posted.append((url, body))
        return (
            b'{"url": "https://mmg.whatsapp.net/v/vid.enc?ccb=1",'
            b' "direct_path": "/v/vid.enc", "handle": ""}'
        )

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_post=_fake_post)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        await client.send_video(chat, _VIDEO_BYTES, mimetype="video/mp4", caption="clip")

        assert posted, "no media upload POST happened"
        assert "/mms/video/" in posted[0][0]

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received an outbound message"
        participants = msgs[0].get_child("participants")
        assert participants is not None
        (to_node,) = participants.get_children("to")
        enc_node = to_node.get_child("enc")
        assert enc_node is not None
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(), client_identity_public=device.identity_public
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        vid = proto.video_message
        assert vid.mimetype == "video/mp4"
        assert vid.caption == "clip"
        assert vid.direct_path == "/v/vid.enc"
        assert vid.file_length == len(_VIDEO_BYTES)
        recovered = decrypt_media(
            posted[0][1],
            vid.media_key,
            MEDIA_VIDEO,
            file_enc_sha256=vid.file_enc_sha256,
            file_sha256=vid.file_sha256,
        )
        assert recovered == _VIDEO_BYTES

        await client.disconnect()


async def test_inbound_voice_note_surfaces_attachment_and_downloads() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    enc = encrypt_media(_AUDIO_BYTES, MEDIA_AUDIO, media_key=_MEDIA_KEY)

    async def _fake_get(url: str) -> bytes:
        assert "mms-type=audio" in url
        return enc.enc_data

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_get=_fake_get)
        client._device = device

        received: list[Message] = []

        @client.on("message")
        async def _on_message(m: Message) -> None:
            received.append(m)

        await _connect(client, server)

        proto = MessageProto()
        aud = proto.audio_message
        aud.direct_path = "/v/t62.7117-24/aud.enc"
        aud.media_key = enc.media_key
        aud.file_sha256 = enc.file_sha256
        aud.file_enc_sha256 = enc.file_enc_sha256
        aud.file_length = enc.file_length
        aud.mimetype = "audio/ogg; codecs=opus"
        aud.ptt = True
        aud.seconds = 4
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(received))
        media = received[0].media
        assert media is not None
        assert media.kind == "audio"
        assert media.ptt is True
        assert media.mimetype == "audio/ogg; codecs=opus"
        assert media.media_type == MEDIA_AUDIO
        assert media.file_length == len(_AUDIO_BYTES)

        plaintext = await client.download_media(media)
        assert plaintext == _AUDIO_BYTES

        await client.disconnect()


async def test_outbound_send_audio_uploads_and_ships_audio_message() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    posted: list[tuple[str, bytes]] = []

    async def _fake_post(url: str, body: bytes) -> bytes:
        posted.append((url, body))
        return (
            b'{"url": "https://mmg.whatsapp.net/v/aud.enc?ccb=1",'
            b' "direct_path": "/v/aud.enc", "handle": ""}'
        )

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_post=_fake_post)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        await client.send_audio(chat, _AUDIO_BYTES, ptt=True)

        assert posted, "no media upload POST happened"
        assert "/mms/audio/" in posted[0][0]

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received an outbound message"
        participants = msgs[0].get_child("participants")
        assert participants is not None
        (to_node,) = participants.get_children("to")
        enc_node = to_node.get_child("enc")
        assert enc_node is not None
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(), client_identity_public=device.identity_public
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        aud = proto.audio_message
        assert aud.ptt is True
        assert aud.mimetype == "audio/ogg; codecs=opus"
        assert aud.direct_path == "/v/aud.enc"
        assert aud.file_length == len(_AUDIO_BYTES)
        recovered = decrypt_media(
            posted[0][1],
            aud.media_key,
            MEDIA_AUDIO,
            file_enc_sha256=aud.file_enc_sha256,
            file_sha256=aud.file_sha256,
        )
        assert recovered == _AUDIO_BYTES

        await client.disconnect()


async def test_outbound_send_document_uploads_and_ships_document_message() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    posted: list[tuple[str, bytes]] = []

    async def _fake_post(url: str, body: bytes) -> bytes:
        posted.append((url, body))
        return (
            b'{"url": "https://mmg.whatsapp.net/v/doc.enc?ccb=1",'
            b' "direct_path": "/v/doc.enc", "handle": ""}'
        )

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url, media_http_post=_fake_post)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        sent = await client.send_document(
            chat,
            _DOC_BYTES,
            mimetype="application/pdf",
            filename="report.pdf",
            caption="Q3 numbers",
        )
        assert sent.from_me

        # The upload POST went to the document endpoint.
        assert posted, "no media upload POST happened"
        assert "/mms/document/" in posted[0][0]

        # The peer can decrypt the shipped stanza to a DocumentMessage
        # whose media fields download + decrypt back to the plaintext.
        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received an outbound message"
        participants = msgs[0].get_child("participants")
        assert participants is not None
        (to_node,) = participants.get_children("to")
        enc_node = to_node.get_child("enc")
        assert enc_node is not None and enc_node.get_str("type") == "pkmsg"
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(), client_identity_public=device.identity_public
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        doc = proto.document_message
        assert doc.mimetype == "application/pdf"
        assert doc.file_name == "report.pdf"
        assert doc.caption == "Q3 numbers"
        assert doc.direct_path == "/v/doc.enc"
        assert doc.file_length == len(_DOC_BYTES)
        recovered = decrypt_media(
            posted[0][1],
            doc.media_key,
            MEDIA_DOCUMENT,
            file_enc_sha256=doc.file_enc_sha256,
            file_sha256=doc.file_sha256,
        )
        assert recovered == _DOC_BYTES

        await client.disconnect()
