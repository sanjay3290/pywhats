# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Issue #37 e2e: a HISTORY_SYNC_NOTIFICATION downloads + decodes + emits.

A self-sent HISTORY_SYNC_NOTIFICATION points at a media blob; the client
downloads it (media CDN GET, injected here), zlib-inflates it, parses the
HistorySync proto, and emits a ``history_sync`` event. Mirrors whatsmeow
handleHistorySyncNotification -> DownloadHistorySync.
"""

from __future__ import annotations

import asyncio
import zlib
from pathlib import Path

import pytest

from pywhats import Client
from pywhats.events import JID
from pywhats.events import HistorySync as HistorySyncEvent
from pywhats.media.crypto import MEDIA_HISTORY
from pywhats.media.upload import encrypt_media
from pywhats.proto import HistorySync as HistorySyncProto
from pywhats.proto import Message as MessageProto
from pywhats.proto import ProtocolMessage
from pywhats.store import save_device_store

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_MEDIA_KEY = b"\x07" * 32


def _history_blob() -> bytes:
    hs = HistorySyncProto()
    hs.sync_type = HistorySyncProto.INITIAL_BOOTSTRAP
    hs.progress = 100
    c = hs.conversations.add()
    c.id = "9990@s.whatsapp.net"
    c.messages.add().message = b"m1"
    c.messages.add().message = b"m2"
    c.messages.add().message = b"m3"
    return zlib.compress(hs.SerializeToString())


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _c() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_history_sync_notification_downloads_and_emits(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    device = paired_device()
    save_device_store(device, session_path)
    own_primary = SignalPeer(jid=JID(user="15551230000", server="s.whatsapp.net", device=0))

    # Encrypt the history blob as the CDN would; the notification carries
    # the matching key + hashes so decrypt_media verifies it.
    enc = encrypt_media(_history_blob(), MEDIA_HISTORY, media_key=_MEDIA_KEY)

    async def _fake_get(url: str) -> bytes:
        return enc.enc_data

    async with FakeWhatsAppServer(peer=own_primary) as server:
        client = Client(session_path=session_path, ws_url=server.url, media_http_get=_fake_get)
        events: list[HistorySyncEvent] = []

        @client.on("history_sync")
        async def _on_hs(evt: HistorySyncEvent) -> None:
            events.append(evt)

        await _connect(client, server)

        proto = MessageProto()
        pm = proto.protocol_message
        pm.type = ProtocolMessage.HISTORY_SYNC_NOTIFICATION
        pm.history_sync_notification.direct_path = "/hist/blob.enc"
        pm.history_sync_notification.media_key = enc.media_key
        pm.history_sync_notification.file_sha256 = enc.file_sha256
        pm.history_sync_notification.file_enc_sha256 = enc.file_enc_sha256
        pm.history_sync_notification.file_length = enc.file_length
        pm.history_sync_notification.sync_type = 0

        await server.deliver_proto(own_primary, proto, client_device=client.device)

        await poll_until(lambda: bool(events), timeout_s=5.0)
        await client.disconnect()

    assert len(events) == 1
    evt = events[0]
    assert evt.sync_type == "INITIAL_BOOTSTRAP"
    assert evt.conversation_count == 1
    assert evt.message_count == 3
    assert evt.conversation_ids == ["9990@s.whatsapp.net"]
