# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media upload: encrypt, POST to the CDN, parse the response (issue #36).

Uploading an attachment is the mirror of downloading it: encrypt the
plaintext under a fresh 32-byte media key, POST the encrypted file to the
media CDN, and read back the ``direct_path`` / ``url`` / ``handle`` the
server assigns. Those fields, plus the media key and the two integrity
hashes, go into the message (e.g. an ``ImageMessage``) that references the
attachment.

Mirrors whatsmeow ``upload.go`` (Upload + rawUpload). The iq round-trip
and HTTP POST are injected so the pipeline is testable without a socket
or network.
"""

from __future__ import annotations

import asyncio
import base64
import json
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.media.crypto import MMS_TYPE, derive_media_keys
from pywhats.media.download import SendIq, build_media_conn_iq, parse_media_conn

__all__ = [
    "EncryptedMedia",
    "UploadResult",
    "MediaUploader",
    "encrypt_media",
    "build_upload_url",
    "default_http_post",
]

HttpPost = Callable[[str, bytes], Awaitable[bytes]]

# whatsmeow socket.Origin — upload requests carry the web-client origin.
_WA_ORIGIN = "https://web.whatsapp.com"


@dataclass(frozen=True)
class EncryptedMedia:
    """An encrypted attachment ready to upload, plus the fields a message needs."""

    enc_data: bytes
    media_key: bytes
    file_enc_sha256: bytes
    file_sha256: bytes
    file_length: int


@dataclass(frozen=True)
class UploadResult:
    """The server's response to an upload, ready to copy into a message."""

    url: str
    direct_path: str
    handle: str
    media_key: bytes
    file_enc_sha256: bytes
    file_sha256: bytes
    file_length: int


def encrypt_media(
    plaintext: bytes, media_type: str, *, media_key: bytes | None = None
) -> EncryptedMedia:
    """Encrypt an attachment exactly as whatsmeow ``Upload`` does.

    A random 32-byte media key derives the iv/cipher/mac keys; the file is
    AES-256-CBC + PKCS#7 encrypted and a 10-byte truncated HMAC-SHA256 is
    appended. ``media_key`` may be pinned for deterministic tests.
    """
    import secrets

    if media_key is None:
        media_key = secrets.token_bytes(32)
    keys = derive_media_keys(media_key, media_type)

    padded = _pkcs7(plaintext)
    enc = Cipher(algorithms.AES(keys.cipher_key), modes.CBC(keys.iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    import hashlib
    import hmac

    mac = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()[:10]
    enc_data = ciphertext + mac
    return EncryptedMedia(
        enc_data=enc_data,
        media_key=media_key,
        file_enc_sha256=hashlib.sha256(enc_data).digest(),
        file_sha256=hashlib.sha256(plaintext).digest(),
        file_length=len(plaintext),
    )


def build_upload_url(host: str, mms_type: str, file_enc_sha256: bytes, auth: str) -> str:
    """Build the upload POST URL (whatsmeow ``rawUpload``).

    ``https://<host>/mms/<mms-type>/<token>?auth=<auth>&token=<token>`` where
    ``token = b64url(fileEncSHA256)``.
    """
    token = base64.urlsafe_b64encode(file_enc_sha256).decode()
    query = urllib.parse.urlencode({"auth": auth, "token": token})
    return f"https://{host}/mms/{mms_type}/{token}?{query}"


class MediaUploader:
    """Encrypts and uploads attachments over an injected iq + HTTP POST layer."""

    def __init__(self, *, send_iq: SendIq, http_post: HttpPost) -> None:
        self._send_iq = send_iq
        self._http_post = http_post

    async def upload(self, plaintext: bytes, media_type: str) -> UploadResult:
        """Encrypt ``plaintext``, POST it to the CDN, and return the result."""
        enc = encrypt_media(plaintext, media_type)
        resp = await self._send_iq(build_media_conn_iq(_new_id()))
        conn = parse_media_conn(resp)
        mms_type = MMS_TYPE.get(media_type, "")
        url = build_upload_url(conn.hosts[0], mms_type, enc.file_enc_sha256, conn.auth)
        raw = await self._http_post(url, enc.enc_data)
        parsed = json.loads(raw)
        return UploadResult(
            url=parsed.get("url", ""),
            direct_path=parsed.get("direct_path", ""),
            handle=parsed.get("handle", ""),
            media_key=enc.media_key,
            file_enc_sha256=enc.file_enc_sha256,
            file_sha256=enc.file_sha256,
            file_length=enc.file_length,
        )


async def default_http_post(url: str, body: bytes, *, timeout: float = 60.0) -> bytes:  # noqa: ASYNC109
    """POST ``body`` to ``url`` with the WA web origin headers, off the loop.

    Uses stdlib :mod:`urllib` in a worker thread (no extra HTTP
    dependency); mirrors whatsmeow's Origin/Referer headers on media
    uploads (upload.go ``rawUpload``).
    """

    def _post() -> bytes:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Origin": _WA_ORIGIN, "Referer": _WA_ORIGIN + "/"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return bytes(resp.read())

    return await asyncio.to_thread(_post)


def _pkcs7(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _new_id() -> str:
    import secrets

    return secrets.token_hex(8).upper()
