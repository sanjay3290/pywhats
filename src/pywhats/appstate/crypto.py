# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Key expansion and per-mutation crypto for app-state sync (issue #35b).

Every app-state root key (stored by #35a) expands into five 32-byte
sub-keys via HKDF-SHA256 (info ``"WhatsApp Mutation Keys"``, 160 bytes):
index, value-encryption, value-MAC, snapshot-MAC, patch-MAC. Mutation
values are AES-256-CBC encrypted and authenticated with an
HMAC-SHA512-truncated content MAC. Mirrors whatsmeow
``appstate/keys.go`` (``expandAppStateKeys``) and ``appstate/hash.go``
(``generateContentMAC``).
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "ExpandedAppStateKeys",
    "hkdf_expand",
    "expand_app_state_keys",
    "generate_content_mac",
    "aes_cbc_decrypt",
]

_MUTATION_KEYS_INFO = b"WhatsApp Mutation Keys"


def hkdf_expand(input_key_material: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 with a zero salt, as WhatsApp uses throughout app-state.

    A zero-length (``None``) salt is defined by RFC 5869 to default to a
    string of ``HashLen`` zero bytes, which is what whatsmeow's
    ``hkdfutil.SHA256`` passes.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(
        input_key_material
    )


@dataclass(frozen=True)
class ExpandedAppStateKeys:
    """The five sub-keys derived from one app-state root key."""

    index: bytes
    value_encryption: bytes
    value_mac: bytes
    snapshot_mac: bytes
    patch_mac: bytes


def expand_app_state_keys(key_data: bytes) -> ExpandedAppStateKeys:
    """Expand a 32-byte root key into the five app-state sub-keys."""
    okm = hkdf_expand(key_data, _MUTATION_KEYS_INFO, 160)
    return ExpandedAppStateKeys(
        index=okm[0:32],
        value_encryption=okm[32:64],
        value_mac=okm[64:96],
        snapshot_mac=okm[96:128],
        patch_mac=okm[128:160],
    )


def generate_content_mac(
    *, operation: int, data: bytes, key_id: bytes, value_mac_key: bytes
) -> bytes:
    """HMAC-SHA512(value_mac_key, op+1 || key_id || data || be8(len(key_id)+1))[:32].

    Matches whatsmeow ``generateContentMAC`` (appstate/hash.go): the
    leading operation byte is ``operation + 1`` so SET and REMOVE over
    the same bytes MAC differently.
    """
    h = hmac.HMAC(value_mac_key, hashes.SHA512())
    h.update(bytes([operation + 1]))
    h.update(key_id)
    h.update(data)
    h.update((len(key_id) + 1).to_bytes(8, "big"))
    return h.finalize()[:32]


def aes_cbc_decrypt(key: bytes, iv_and_ciphertext: bytes) -> bytes:
    """Decrypt an IV-prefixed AES-256-CBC blob and strip PKCS#7 padding.

    The first 16 bytes are the IV, the rest the ciphertext — the layout
    whatsmeow's ``cbcutil.Decrypt`` consumes after splitting the value
    blob.
    """
    iv, ciphertext = iv_and_ciphertext[:16], iv_and_ciphertext[16:]
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
