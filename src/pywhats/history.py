# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""History sync: download + inflate + parse HISTORY_SYNC_NOTIFICATION (issue #37).

On first link the phone self-sends ``HISTORY_SYNC_NOTIFICATION`` protocol
messages, each pointing at a media blob holding a chunk of initial chat
history. This downloads that blob with the #36 media primitives (media
type ``"WhatsApp History Keys"``), zlib-inflates it, parses the
``HistorySync`` protobuf, and surfaces a summary as a ``history_sync``
event.

Mirrors whatsmeow ``DownloadHistorySync`` (message.go): download ->
``zlib`` inflate -> ``proto.Unmarshal`` -> dispatch. The full blob also
carries per-message ``WebMessageInfo`` records; those are kept opaque for
now and only counted.
"""

from __future__ import annotations

import logging
import zlib
from collections.abc import Awaitable, Callable
from typing import Protocol

from pywhats.events import HistorySync
from pywhats.media.crypto import MEDIA_HISTORY
from pywhats.media.download import MediaInfo
from pywhats.proto import HistorySync as _HistorySyncProto

__all__ = ["parse_history_sync", "HistorySyncer"]

_log = logging.getLogger("pywhats.history")

_SYNC_TYPE_NAMES = _HistorySyncProto.HistorySyncType.keys()


def parse_history_sync(compressed: bytes) -> HistorySync:
    """Inflate + parse a history-sync blob into a :class:`HistorySync` event."""
    raw = zlib.decompress(compressed)
    hs = _HistorySyncProto()
    hs.ParseFromString(raw)

    conversation_ids = [c.id for c in hs.conversations]
    message_count = sum(len(c.messages) for c in hs.conversations)
    pushnames = [(p.id, p.pushname) for p in hs.pushnames]
    return HistorySync(
        sync_type=_sync_type_name(hs.sync_type),
        progress=int(hs.progress),
        chunk_order=int(hs.chunk_order),
        conversation_count=len(hs.conversations),
        message_count=message_count,
        conversation_ids=conversation_ids,
        pushnames=pushnames,
    )


def _sync_type_name(value: int) -> str:
    try:
        return str(_SYNC_TYPE_NAMES[value])
    except (IndexError, TypeError):
        return str(value)


class _Downloader(Protocol):
    async def download(self, info: MediaInfo) -> bytes: ...


class HistorySyncer:
    """Downloads and dispatches history-sync notifications.

    Backs the receiver's HISTORY_SYNC_NOTIFICATION handling: given the
    notification's media fields it downloads the blob, parses it, and
    emits a ``history_sync`` event. Runs in a background task since the
    download does its own iq + HTTP round-trips.
    """

    def __init__(
        self, *, downloader: _Downloader, emit: Callable[[str, object], Awaitable[None]]
    ) -> None:
        self._downloader = downloader
        self._emit = emit

    async def handle(self, notif: object) -> None:
        info = MediaInfo(
            direct_path=notif.direct_path,  # type: ignore[attr-defined]
            media_key=notif.media_key,  # type: ignore[attr-defined]
            file_sha256=notif.file_sha256,  # type: ignore[attr-defined]
            file_enc_sha256=notif.file_enc_sha256,  # type: ignore[attr-defined]
            media_type=MEDIA_HISTORY,
        )
        try:
            blob = await self._downloader.download(info)
            event = parse_history_sync(blob)
        except Exception:  # noqa: BLE001
            _log.exception("history sync: failed to download/parse notification")
            return
        _log.info(
            "history sync: %s chunk=%d progress=%d convos=%d msgs=%d",
            event.sync_type,
            event.chunk_order,
            event.progress,
            event.conversation_count,
            event.message_count,
        )
        await self._emit("history_sync", event)
