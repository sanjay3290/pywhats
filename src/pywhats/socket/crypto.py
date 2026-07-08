# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Primitive cryptographic helpers used by the Noise XX handshake.

This module intentionally stays tiny: one function per primitive, thin wrappers
over ``cryptography`` that encode the exact conventions required by the Noise
Protocol Framework specification (sections cited inline).

Design rules:

* Never log key material at any level.
* Use constant-time comparisons for anything MAC-shaped (``hmac.compare_digest``).
* Let AEAD authentication failures propagate as ``InvalidTag`` — callers wrap
  them into :class:`pywhats.errors.HandshakeError` without leaking state.

References:

* Noise Protocol Framework spec v34 — https://noiseprotocol.org/noise.html
* ``cryptography`` library — https://cryptography.io/
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = [
    "DHLEN",
    "HASHLEN",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "private_to_public",
    "dh",
    "hash_sha256",
    "hmac_sha256",
    "hkdf",
    "aead_encrypt",
    "aead_decrypt",
    "build_nonce_chachapoly",
    "build_nonce_aesgcm",
]

# Noise spec 4.1 (25519): DHLEN = 32.
DHLEN = 32
# Noise spec 4.2 (SHA256): HASHLEN = 32.
HASHLEN = 32


# ---- X25519 ---------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh X25519 keypair.

    Returns ``(private_32, public_32)`` both as raw 32-byte sequences.
    """
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    pub = sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return priv, pub


def load_private_key(priv: bytes) -> X25519PrivateKey:
    if len(priv) != DHLEN:
        raise ValueError("X25519 private key must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(priv)


def load_public_key(pub: bytes) -> X25519PublicKey:
    if len(pub) != DHLEN:
        raise ValueError("X25519 public key must be 32 bytes")
    return X25519PublicKey.from_public_bytes(pub)


def private_to_public(priv: bytes) -> bytes:
    """Derive the 32-byte X25519 public key from a 32-byte private key."""
    return (
        load_private_key(priv)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def dh(priv: bytes, pub: bytes) -> bytes:
    """Noise spec 4.1: DH(priv, pub) for 25519 returns a 32-byte shared secret."""
    return load_private_key(priv).exchange(load_public_key(pub))


# ---- Hash + HMAC ----------------------------------------------------------


def hash_sha256(data: bytes) -> bytes:
    """Noise spec 4.2: HASH() for SHA256."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256. Used as the PRF inside HKDF (Noise spec 4.3)."""
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> tuple[bytes, ...]:
    """Noise spec 4.3: HKDF with zero-length info, SHA256 PRF.

    Returns ``num_outputs`` HASHLEN-byte outputs (2 or 3).
    """
    if num_outputs not in (2, 3):
        raise ValueError("HKDF num_outputs must be 2 or 3")
    # Noise spec 4.3: temp_key = HMAC-HASH(chaining_key, input_key_material)
    temp_key = hmac_sha256(chaining_key, input_key_material)
    # Noise spec 4.3: output1 = HMAC-HASH(temp_key, byte(0x01))
    output1 = hmac_sha256(temp_key, b"\x01")
    # Noise spec 4.3: output2 = HMAC-HASH(temp_key, output1 || byte(0x02))
    output2 = hmac_sha256(temp_key, output1 + b"\x02")
    if num_outputs == 2:
        return output1, output2
    # Noise spec 4.3: output3 = HMAC-HASH(temp_key, output2 || byte(0x03))
    output3 = hmac_sha256(temp_key, output2 + b"\x03")
    return output1, output2, output3


# ---- AEAD nonce encoding --------------------------------------------------


def build_nonce_chachapoly(counter: int) -> bytes:
    """Noise spec 5.1 / ChaChaPoly: 32 zero bits || little-endian(counter)."""
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("nonce counter out of range")
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")


def build_nonce_aesgcm(counter: int) -> bytes:
    """Noise spec 5.1 / AESGCM: 32 zero bits || big-endian(counter)."""
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("nonce counter out of range")
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")


# ---- AEAD -----------------------------------------------------------------


def aead_encrypt(cipher_name: str, key: bytes, counter: int, ad: bytes, plaintext: bytes) -> bytes:
    """AEAD ENCRYPT per Noise spec 4.2 / 5.1.

    ``cipher_name`` is either ``"ChaChaPoly"`` or ``"AESGCM"``. Output is
    ``ciphertext || tag`` with a 16-byte authentication tag appended, per
    the Noise framework requirement on authenticated ciphers.
    """
    if cipher_name == "ChaChaPoly":
        nonce = build_nonce_chachapoly(counter)
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)
    if cipher_name == "AESGCM":
        nonce = build_nonce_aesgcm(counter)
        return AESGCM(key).encrypt(nonce, plaintext, ad)
    raise ValueError(f"unsupported cipher: {cipher_name}")


def aead_decrypt(cipher_name: str, key: bytes, counter: int, ad: bytes, ciphertext: bytes) -> bytes:
    """AEAD DECRYPT per Noise spec 4.2 / 5.1.

    On authentication failure, the underlying library raises
    ``cryptography.exceptions.InvalidTag``. Callers should translate that
    into a :class:`HandshakeError` without leaking any key/nonce/tag state
    in the message.
    """
    if cipher_name == "ChaChaPoly":
        nonce = build_nonce_chachapoly(counter)
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)
    if cipher_name == "AESGCM":
        nonce = build_nonce_aesgcm(counter)
        return AESGCM(key).decrypt(nonce, ciphertext, ad)
    raise ValueError(f"unsupported cipher: {cipher_name}")


# ---- Utility --------------------------------------------------------------


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality; thin wrapper around :func:`hmac.compare_digest`."""
    return hmac.compare_digest(a, b)
