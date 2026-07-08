# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media download crypto: key derivation + verify/decrypt (issue #36).

Mirrors whatsmeow ``download.go`` (``getMediaKeys`` /
``downloadAndDecrypt`` / ``validateMedia``). Each test encrypts a
plaintext exactly as the WhatsApp sender would, then decrypts it back and
checks every authentication layer.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.media.crypto import (
    MEDIA_APP_STATE,
    MEDIA_IMAGE,
    MediaEncSha256Mismatch,
    MediaHmacMismatch,
    MediaSha256Mismatch,
    decrypt_media,
    derive_media_keys,
)


def _pkcs7(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _encrypt_as_sender(
    plaintext: bytes, media_key: bytes, media_type: str
) -> tuple[bytes, bytes, bytes]:
    """Return (enc_file, file_enc_sha256, file_sha256) the way WA encrypts media."""
    keys = derive_media_keys(media_key, media_type)
    enc = Cipher(algorithms.AES(keys.cipher_key), modes.CBC(keys.iv)).encryptor()
    ciphertext = enc.update(_pkcs7(plaintext)) + enc.finalize()
    mac = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()[:10]
    enc_file = ciphertext + mac
    return enc_file, hashlib.sha256(enc_file).digest(), hashlib.sha256(plaintext).digest()


def test_derive_media_keys_lengths_and_split() -> None:
    keys = derive_media_keys(b"\x11" * 32, MEDIA_IMAGE)
    assert len(keys.iv) == 16
    assert len(keys.cipher_key) == 32
    assert len(keys.mac_key) == 32


def test_derive_media_keys_differ_by_media_type() -> None:
    mk = b"\x22" * 32
    assert (
        derive_media_keys(mk, MEDIA_IMAGE).cipher_key
        != derive_media_keys(mk, MEDIA_APP_STATE).cipher_key
    )


def test_round_trip_decrypts_plaintext() -> None:
    plaintext = b"hello media world, this spans multiple AES blocks!!" * 3
    media_key = b"\x33" * 32
    enc_file, enc_sha, sha = _encrypt_as_sender(plaintext, media_key, MEDIA_IMAGE)

    out = decrypt_media(enc_file, media_key, MEDIA_IMAGE, file_enc_sha256=enc_sha, file_sha256=sha)
    assert out == plaintext


def test_wrong_enc_sha256_raises() -> None:
    media_key = b"\x44" * 32
    enc_file, _, sha = _encrypt_as_sender(b"payload data 123", media_key, MEDIA_IMAGE)
    with pytest.raises(MediaEncSha256Mismatch):
        decrypt_media(
            enc_file, media_key, MEDIA_IMAGE, file_enc_sha256=b"\x00" * 32, file_sha256=sha
        )


def test_tampered_ciphertext_fails_hmac() -> None:
    media_key = b"\x55" * 32
    enc_file, enc_sha, sha = _encrypt_as_sender(b"payload data 456", media_key, MEDIA_IMAGE)
    tampered = bytearray(enc_file)
    tampered[0] ^= 0xFF
    # Recompute enc sha so we reach the HMAC check (not the enc-sha gate).
    bad_enc_sha = hashlib.sha256(bytes(tampered)).digest()
    with pytest.raises(MediaHmacMismatch):
        decrypt_media(
            bytes(tampered), media_key, MEDIA_IMAGE, file_enc_sha256=bad_enc_sha, file_sha256=sha
        )


def test_wrong_plaintext_sha256_raises() -> None:
    media_key = b"\x66" * 32
    enc_file, enc_sha, _ = _encrypt_as_sender(b"payload data 789", media_key, MEDIA_IMAGE)
    with pytest.raises(MediaSha256Mismatch):
        decrypt_media(
            enc_file, media_key, MEDIA_IMAGE, file_enc_sha256=enc_sha, file_sha256=b"\x00" * 32
        )


def test_too_short_file_raises() -> None:
    with pytest.raises(ValueError):
        decrypt_media(b"\x00" * 5, b"\x77" * 32, MEDIA_IMAGE, file_enc_sha256=b"", file_sha256=b"")
