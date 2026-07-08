# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media encryption keys + download verify/decrypt (issue #36).

Every WhatsApp attachment is AES-256-CBC encrypted under keys derived
from a random 32-byte ``mediaKey`` via HKDF-SHA256, and authenticated
with a truncated HMAC-SHA256 plus two SHA-256 integrity hashes. The
``info`` string in the HKDF is the media type (``"WhatsApp Image Keys"``
etc.), so the same key material can never be reused across types.

:func:`decrypt_media` runs the whole download-side pipeline in the same
order as whatsmeow ``downloadAndDecrypt`` (download.go):

    1. the last 10 bytes of the downloaded file are the HMAC;
    2. ``sha256(whole file) == file_enc_sha256`` (transport integrity);
    3. ``HMAC-SHA256(macKey, iv || ciphertext)[:10] == mac``;
    4. AES-CBC decrypt with the derived iv + key, strip PKCS#7;
    5. ``sha256(plaintext) == file_sha256`` (content integrity).

Mirrors whatsmeow ``getMediaKeys`` / ``validateMedia`` /
``downloadEncryptedMedia`` (download.go).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.appstate.crypto import hkdf_expand

__all__ = [
    "MEDIA_IMAGE",
    "MEDIA_VIDEO",
    "MEDIA_AUDIO",
    "MEDIA_DOCUMENT",
    "MEDIA_HISTORY",
    "MEDIA_APP_STATE",
    "MMS_TYPE",
    "MediaKeys",
    "MediaError",
    "MediaEncSha256Mismatch",
    "MediaHmacMismatch",
    "MediaSha256Mismatch",
    "derive_media_keys",
    "decrypt_media",
]

# HKDF info strings (whatsmeow download.go MediaType constants).
MEDIA_IMAGE = "WhatsApp Image Keys"
MEDIA_VIDEO = "WhatsApp Video Keys"
MEDIA_AUDIO = "WhatsApp Audio Keys"
MEDIA_DOCUMENT = "WhatsApp Document Keys"
MEDIA_HISTORY = "WhatsApp History Keys"
MEDIA_APP_STATE = "WhatsApp App State Keys"

# media type -> mms-type URL param (whatsmeow mediaTypeToMMSType).
MMS_TYPE = {
    MEDIA_IMAGE: "image",
    MEDIA_VIDEO: "video",
    MEDIA_AUDIO: "audio",
    MEDIA_DOCUMENT: "document",
    MEDIA_HISTORY: "md-msg-hist",
    MEDIA_APP_STATE: "md-app-state",
}

_MAC_LENGTH = 10


class MediaError(Exception):
    """Base for media download verification failures."""


class MediaEncSha256Mismatch(MediaError):
    """The downloaded (still-encrypted) file's SHA-256 did not match."""


class MediaHmacMismatch(MediaError):
    """The media HMAC did not verify — the file is untrusted."""


class MediaSha256Mismatch(MediaError):
    """The decrypted plaintext's SHA-256 did not match."""


@dataclass(frozen=True)
class MediaKeys:
    """The iv + cipher/mac keys derived from a media key for one type."""

    iv: bytes
    cipher_key: bytes
    mac_key: bytes
    ref_key: bytes


def derive_media_keys(media_key: bytes, media_type: str) -> MediaKeys:
    """Expand a 32-byte media key into iv/cipher/mac keys (whatsmeow ``getMediaKeys``).

    HKDF-SHA256(media_key, salt=0, info=media_type, 112 bytes) →
    iv[:16], cipherKey[16:48], macKey[48:80], refKey[80:112].
    """
    okm = hkdf_expand(media_key, media_type.encode(), 112)
    return MediaKeys(iv=okm[:16], cipher_key=okm[16:48], mac_key=okm[48:80], ref_key=okm[80:112])


def decrypt_media(
    enc_file: bytes,
    media_key: bytes,
    media_type: str,
    *,
    file_enc_sha256: bytes,
    file_sha256: bytes,
) -> bytes:
    """Verify and decrypt a downloaded encrypted media file.

    ``enc_file`` is the raw CDN download (ciphertext followed by the
    10-byte HMAC). Raises a :class:`MediaError` subclass if any layer
    fails to authenticate.
    """
    if len(enc_file) <= _MAC_LENGTH:
        raise ValueError(f"media file too short: {len(enc_file)} bytes")

    if file_enc_sha256 and hashlib.sha256(enc_file).digest() != file_enc_sha256:
        raise MediaEncSha256Mismatch("downloaded media enc-SHA256 mismatch")

    ciphertext, mac = enc_file[:-_MAC_LENGTH], enc_file[-_MAC_LENGTH:]
    keys = derive_media_keys(media_key, media_type)

    expected = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()[:_MAC_LENGTH]
    if not hmac.compare_digest(expected, mac):
        raise MediaHmacMismatch("media HMAC mismatch")

    plaintext = _aes_cbc_decrypt(keys.cipher_key, keys.iv, ciphertext)

    if file_sha256 and hashlib.sha256(plaintext).digest() != file_sha256:
        raise MediaSha256Mismatch("decrypted media SHA256 mismatch")
    return plaintext


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError(f"ciphertext is not a multiple of the block size: {len(ciphertext)}")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 16 or pad > len(padded):
        raise ValueError("invalid PKCS#7 padding")
    if padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return padded[:-pad]
