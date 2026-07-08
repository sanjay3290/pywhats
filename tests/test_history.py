# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""History sync: parse the decompressed blob + the download/emit path (issue #37).

Mirrors whatsmeow ``DownloadHistorySync`` (message.go): download the
HISTORY_SYNC_NOTIFICATION media blob, zlib-inflate it, parse the
HistorySync proto, and surface it. The download uses the #36 media
primitives.
"""

from __future__ import annotations

import zlib

import pytest

from pywhats.events import HistorySync as HistorySyncEvent
from pywhats.history import HistorySyncer, parse_history_sync
from pywhats.proto import HistorySync as HistorySyncProto


def _make_blob() -> bytes:
    hs = HistorySyncProto()
    hs.sync_type = HistorySyncProto.INITIAL_BOOTSTRAP
    hs.progress = 100
    hs.chunk_order = 1
    c = hs.conversations.add()
    c.id = "111@s.whatsapp.net"
    c.name = "Alice"
    c.messages.add().message = b"opaque-1"
    c.messages.add().message = b"opaque-2"
    p = hs.pushnames.add()
    p.id = "222@s.whatsapp.net"
    p.pushname = "Bob"
    return zlib.compress(hs.SerializeToString())


def test_parse_history_sync_surfaces_summary() -> None:
    evt = parse_history_sync(_make_blob())
    assert isinstance(evt, HistorySyncEvent)
    assert evt.sync_type == "INITIAL_BOOTSTRAP"
    assert evt.progress == 100
    assert evt.chunk_order == 1
    assert evt.conversation_count == 1
    assert evt.message_count == 2
    assert evt.pushnames == [("222@s.whatsapp.net", "Bob")]
    assert evt.conversation_ids == ["111@s.whatsapp.net"]


def test_parse_history_sync_push_name_type() -> None:
    hs = HistorySyncProto()
    hs.sync_type = HistorySyncProto.PUSH_NAME
    p = hs.pushnames.add()
    p.id = "1@s.whatsapp.net"
    p.pushname = "Carol"
    evt = parse_history_sync(zlib.compress(hs.SerializeToString()))
    assert evt.sync_type == "PUSH_NAME"
    assert evt.pushnames == [("1@s.whatsapp.net", "Carol")]


@pytest.mark.asyncio
async def test_history_syncer_downloads_parses_and_emits() -> None:
    blob = _make_blob()

    class _Downloader:
        def __init__(self) -> None:
            self.info = None

        async def download(self, info: object) -> bytes:
            self.info = info
            return blob

    emitted: list[tuple[str, object]] = []

    async def _emit(event: str, payload: object) -> None:
        emitted.append((event, payload))

    downloader = _Downloader()
    syncer = HistorySyncer(downloader=downloader, emit=_emit)

    class _Notif:
        direct_path = "/hist/blob.enc"
        media_key = b"\x01" * 32
        file_sha256 = b"\x02" * 32
        file_enc_sha256 = b"\x03" * 32

    await syncer.handle(_Notif())

    assert emitted and emitted[0][0] == "history_sync"
    evt = emitted[0][1]
    assert isinstance(evt, HistorySyncEvent)
    assert evt.conversation_count == 1
    # The notification's download fields were threaded into the MediaInfo.
    from pywhats.media.crypto import MEDIA_HISTORY

    assert downloader.info.media_type == MEDIA_HISTORY
    assert downloader.info.direct_path == "/hist/blob.enc"
