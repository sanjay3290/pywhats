# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media download: media-conn host list, CDN URL, and the downloader (issue #36).

To download an attachment the client first asks the server for a set of
media CDN hosts (``<iq xmlns="w:m"><media_conn/></iq>``), then GETs the
message's ``direct_path`` from one of them and decrypts the result with
:func:`pywhats.media.crypto.decrypt_media`. Hosts are tried in order so a
single dead edge doesn't fail the download.

Mirrors whatsmeow ``mediaconn.go`` (queryMediaConn) + ``download.go``
(DownloadMediaWithPath / downloadAndDecrypt). The blocking HTTP GET and
the iq round-trip are injected so the pipeline is unit-testable without a
socket or network; the client supplies the real implementations.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import urllib.request
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pywhats.binary import Node
from pywhats.events import JID
from pywhats.media.crypto import MEDIA_APP_STATE, MMS_TYPE, decrypt_media

__all__ = [
    "MediaConn",
    "MediaInfo",
    "MediaDownloader",
    "build_media_conn_iq",
    "parse_media_conn",
    "build_download_url",
    "default_http_get",
]

# whatsmeow socket.Origin — media CDN requests carry the web-client origin.
_WA_ORIGIN = "https://web.whatsapp.com"

_log = logging.getLogger("pywhats.media.download")

_SERVER = JID(user="", server="s.whatsapp.net")

SendIq = Callable[[Node], Awaitable[Node]]
HttpGet = Callable[[str], Awaitable[bytes]]


@dataclass(frozen=True)
class MediaConn:
    """The media CDN host list + auth token from a ``w:m`` query."""

    hosts: list[str]
    auth: str = ""
    ttl: int = 0


@dataclass(frozen=True)
class MediaInfo:
    """Everything needed to download and decrypt one attachment."""

    direct_path: str
    media_key: bytes
    file_sha256: bytes
    file_enc_sha256: bytes
    media_type: str
    mms_type: str = ""


def build_media_conn_iq(iq_id: str) -> Node:
    """Build the ``<iq xmlns="w:m" type="set"><media_conn/></iq>`` query."""
    return Node(
        tag="iq",
        attrs={"id": iq_id, "type": "set", "xmlns": "w:m", "to": _SERVER},
        content=[Node(tag="media_conn")],
    )


def parse_media_conn(iq: Node) -> MediaConn:
    """Parse the ``<media_conn>`` reply into a :class:`MediaConn`."""
    mc = iq.get_child("media_conn")
    if mc is None:
        raise ValueError("media_conn response missing <media_conn>")
    hosts = [h.get_str("hostname") for h in mc.get_children("host") if h.get_str("hostname")]
    if not hosts:
        raise ValueError("media_conn response has no hosts")
    ttl_raw = mc.get_str("ttl")
    return MediaConn(hosts=hosts, auth=mc.get_str("auth"), ttl=int(ttl_raw) if ttl_raw else 0)


def build_download_url(host: str, direct_path: str, enc_file_hash: bytes, mms_type: str) -> str:
    """Build the CDN download URL (whatsmeow ``DownloadMediaWithPath``).

    ``https://<host><direct_path>&hash=<b64url(encFileHash)>&mms-type=<t>&__wa-mms=``
    """
    if not direct_path.startswith("/"):
        raise ValueError(f"media direct_path must start with '/': {direct_path!r}")
    hash_param = base64.urlsafe_b64encode(enc_file_hash).decode()
    return f"https://{host}{direct_path}&hash={hash_param}&mms-type={mms_type}&__wa-mms="


class MediaDownloader:
    """Downloads and decrypts attachments over an injected iq + HTTP layer."""

    def __init__(self, *, send_iq: SendIq, http_get: HttpGet) -> None:
        self._send_iq = send_iq
        self._http_get = http_get
        self._conn: MediaConn | None = None

    async def _media_conn(self) -> MediaConn:
        if self._conn is None:
            resp = await self._send_iq(build_media_conn_iq(_new_id()))
            self._conn = parse_media_conn(resp)
        return self._conn

    async def download(self, info: MediaInfo) -> bytes:
        """Fetch and decrypt one attachment, trying each media host in turn."""
        conn = await self._media_conn()
        mms_type = info.mms_type or MMS_TYPE.get(info.media_type, "")
        last_error: Exception | None = None
        for i, host in enumerate(conn.hosts):
            url = build_download_url(host, info.direct_path, info.file_enc_sha256, mms_type)
            try:
                enc_file = await self._http_get(url)
                return decrypt_media(
                    enc_file,
                    info.media_key,
                    info.media_type,
                    file_enc_sha256=info.file_enc_sha256,
                    file_sha256=info.file_sha256,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if i < len(conn.hosts) - 1:
                    _log.warning("media download from %s failed (%s); trying next host", host, exc)
        raise last_error if last_error is not None else RuntimeError("no media hosts to try")

    async def download_external_blob(self, ref: object) -> bytes:
        """Download an app-state ``ExternalBlobReference`` to its plaintext bytes.

        The plaintext is a serialized ``SyncdSnapshot`` / ``SyncdMutations``
        (app-state uses the ``MediaAppState`` key type). Backs
        :class:`pywhats.appstate.fetch.AppStateSyncer`'s ``download_external``.
        """
        info = MediaInfo(
            direct_path=ref.direct_path,  # type: ignore[attr-defined]
            media_key=ref.media_key,  # type: ignore[attr-defined]
            file_sha256=ref.file_sha256,  # type: ignore[attr-defined]
            file_enc_sha256=ref.file_enc_sha256,  # type: ignore[attr-defined]
            media_type=MEDIA_APP_STATE,
        )
        return await self.download(info)


def _new_id() -> str:
    # A local id generator, kept here to avoid importing the messaging
    # package (which would create an appstate<->messaging import cycle).
    import secrets

    return secrets.token_hex(8).upper()


async def default_http_get(url: str, *, timeout: float = 30.0) -> bytes:  # noqa: ASYNC109
    """GET ``url`` with the WhatsApp web origin headers, off the event loop.

    Uses the stdlib :mod:`urllib` in a worker thread so no extra HTTP
    dependency is pulled in; the blocking read runs via
    :func:`asyncio.to_thread`. whatsmeow sets the same Origin/Referer
    headers on media CDN requests (download.go ``doMediaDownloadRequest``).
    """

    def _get() -> bytes:
        req = urllib.request.Request(
            url,
            headers={"Origin": _WA_ORIGIN, "Referer": _WA_ORIGIN + "/"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return bytes(resp.read())

    return await asyncio.to_thread(_get)
