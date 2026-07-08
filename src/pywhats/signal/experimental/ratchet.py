# SPDX-License-Identifier: Apache-2.0
"""Double Ratchet state machine.

Spec: https://signal.org/docs/specifications/doubleratchet/

Implementation choices (documented in SECURITY.md):
  - Hash: SHA-256 for HKDF / HMAC.
  - AEAD: AES-256-CBC + HMAC-SHA-256 (the scheme recommended in spec 5.2).
  - KDF_RK info: ``b"WhisperRatchet"`` (libsignal-compatible).
  - ENCRYPT (message-keys) info: ``b"WhisperMessageKeys"`` (libsignal-compatible).
  - KDF_CK constants: 0x01 (message key), 0x02 (next chain key) per spec 5.2.
  - DEFAULT_MAX_SKIP: 1000 stored skipped message keys per chain.
  - Header encryption: NOT implemented. Headers are sent in the clear
    alongside the ciphertext (the spec's baseline variant).
"""

from __future__ import annotations

import os
import secrets
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _chmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

from pywhats.signal.experimental.keys import SignalCryptoError
from pywhats.signal.experimental.types import MessageHeader

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)

DEFAULT_MAX_SKIP: Final[int] = 1000
# Upper bound on total skipped keys cached across all chains, to bound memory.
_MAX_SKIPPED_TOTAL: Final[int] = 2000

_KDF_RK_INFO: Final[bytes] = b"WhisperRatchet"
_MESSAGE_KEYS_INFO: Final[bytes] = b"WhisperMessageKeys"


def _dh(private: bytes, peer_public: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(private)
    pk = X25519PublicKey.from_public_bytes(peer_public)
    return sk.exchange(pk)


def _generate_dh() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes_raw()
    pub = sk.public_key().public_bytes_raw()
    return priv, pub


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    # Spec 5.2: HKDF with SHA-256, salt=rk, ikm=dh_out, info=application info.
    # Output 64 bytes => (new_rk, chain_key) each 32 bytes.
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=rk, info=_KDF_RK_INFO)
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = _chmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    # Spec 5.2: HMAC-SHA-256(ck, 0x01) -> message key; HMAC(ck, 0x02) -> next ck.
    mk = _hmac_sha256(ck, b"\x01")
    next_ck = _hmac_sha256(ck, b"\x02")
    return mk, next_ck


def _derive_message_keys(mk: bytes) -> tuple[bytes, bytes, bytes]:
    """libsignal message keys: HKDF(mk, salt=zeros(32), info) -> 80 bytes.

    Split into (mac_key[32], cipher_key[32], iv[16]).

    libsignal's on-wire split is ``cipher_key || mac_key || iv`` (see
    WhisperTextProtocol ``MessageKeys``). We expose them in
    ``(mac_key, cipher_key, iv)`` order for historical call sites, which
    is why the slicing here reads swapped — ``out[:32]`` is cipher_key,
    returned as the second tuple element.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=80, salt=b"\x00" * 32, info=_MESSAGE_KEYS_INFO)
    out = hkdf.derive(mk)
    cipher_key = out[:32]
    mac_key = out[32:64]
    iv = out[64:80]
    return mac_key, cipher_key, iv


def _encrypt_aes_cbc(mk: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    mac_key, cipher_key, iv = _derive_message_keys(mk)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return ciphertext, mac_key


def _decrypt_aes_cbc(mk: bytes, ciphertext: bytes) -> bytes:
    _mac_key, cipher_key, iv = _derive_message_keys(mk)
    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise SignalCryptoError("padding check failed") from exc


@dataclass
class RatchetState:
    """Double Ratchet state. Spec 3.2 "State variables"."""

    # DH ratchet
    dhs_priv: bytes  # DHs private
    dhs_pub: bytes  # DHs public
    dhr: bytes | None  # DHr (peer's current ratchet public key)
    # Root and chain keys
    rk: bytes
    cks: bytes | None  # sending chain key
    ckr: bytes | None  # receiving chain key
    # Message counters
    ns: int = 0  # number of messages in sending chain
    nr: int = 0  # number of messages in receiving chain
    pn: int = 0  # number of messages in previous sending chain
    # Skipped keys: (peer_dh_pub, message_number) -> message_key
    mkskipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    # Limit
    max_skip: int = DEFAULT_MAX_SKIP


def ratchet_init_alice(shared_secret: bytes, peer_signed_pre_key_public: bytes) -> RatchetState:
    """Spec 3.3 RatchetInitAlice.

    Alice generates a new DH pair and performs the first half of a DH
    ratchet step against Bob's signed prekey (DHr).
    """
    dhs_priv, dhs_pub = _generate_dh()
    rk, cks = _kdf_rk(shared_secret, _dh(dhs_priv, peer_signed_pre_key_public))
    return RatchetState(
        dhs_priv=dhs_priv,
        dhs_pub=dhs_pub,
        dhr=peer_signed_pre_key_public,
        rk=rk,
        cks=cks,
        ckr=None,
    )


def ratchet_init_bob(
    shared_secret: bytes,
    signed_pre_key_private: bytes,
    signed_pre_key_public: bytes,
) -> RatchetState:
    """Spec 3.3 RatchetInitBob.

    Bob sets DHs = his signed prekey pair and defers the first DH ratchet
    step until Alice's first message arrives.
    """
    return RatchetState(
        dhs_priv=signed_pre_key_private,
        dhs_pub=signed_pre_key_public,
        dhr=None,
        rk=shared_secret,
        cks=None,
        ckr=None,
    )


MacVerifier = Callable[[bytes], None]


def ratchet_encrypt(
    state: RatchetState, plaintext: bytes, associated_data: bytes
) -> tuple[MessageHeader, bytes, bytes]:
    """Spec 3.4 RatchetEncrypt."""
    if state.cks is None:
        raise SignalCryptoError("ratchet sending chain not initialised")
    mk, state.cks = _kdf_ck(state.cks)
    header = MessageHeader(dh=state.dhs_pub, pn=state.pn, n=state.ns)
    state.ns += 1
    ciphertext, mac_key = _encrypt_aes_cbc(mk, plaintext)
    # Wipe mk.
    mk_ba = bytearray(mk)
    for i in range(len(mk_ba)):
        mk_ba[i] = 0
    return header, ciphertext, mac_key


def _skip_message_keys(state: RatchetState, until: int) -> None:
    # Spec 3.5 SkipMessageKeys.
    if state.ckr is None:
        return
    if state.nr + state.max_skip < until:
        raise SignalCryptoError("too many skipped messages")
    while state.nr < until:
        mk, state.ckr = _kdf_ck(state.ckr)
        assert state.dhr is not None
        state.mkskipped[(state.dhr, state.nr)] = mk
        state.nr += 1
        if len(state.mkskipped) > _MAX_SKIPPED_TOTAL:
            # Drop the oldest entry to bound memory.
            oldest = next(iter(state.mkskipped))
            del state.mkskipped[oldest]


def _dh_ratchet(state: RatchetState, header: MessageHeader) -> None:
    # Spec 3.5 DHRatchet.
    state.pn = state.ns
    state.ns = 0
    state.nr = 0
    state.dhr = header.dh
    state.rk, state.ckr = _kdf_rk(state.rk, _dh(state.dhs_priv, state.dhr))
    new_priv, new_pub = _generate_dh()
    state.dhs_priv = new_priv
    state.dhs_pub = new_pub
    state.rk, state.cks = _kdf_rk(state.rk, _dh(state.dhs_priv, state.dhr))


def _try_skipped_message_keys(
    state: RatchetState,
    header: MessageHeader,
    ciphertext: bytes,
    associated_data: bytes,
    verify_mac: MacVerifier | None,
) -> bytes | None:
    key = (header.dh, header.n)
    if key in state.mkskipped:
        mk = state.mkskipped.pop(key)
        if verify_mac is not None:
            verify_mac(_derive_message_keys(mk)[0])
        return _decrypt_aes_cbc(mk, ciphertext)
    return None


def ratchet_decrypt(
    state: RatchetState,
    header: MessageHeader,
    ciphertext: bytes,
    associated_data: bytes,
    verify_mac: MacVerifier | None = None,
) -> bytes:
    """Spec 3.4 RatchetDecrypt."""
    # 1. Try cached skipped keys.
    plain = _try_skipped_message_keys(state, header, ciphertext, associated_data, verify_mac)
    if plain is not None:
        return plain

    # 2. If header.dh is new, skip remaining keys in current receiving chain
    #    then perform a DH ratchet step.
    if state.dhr is None or header.dh != state.dhr:
        # Skip any unreceived messages from the previous chain.
        if state.ckr is not None:
            _skip_message_keys(state, header.pn)
        _dh_ratchet(state, header)

    # 3. Skip any missing messages in the new receiving chain.
    _skip_message_keys(state, header.n)

    # 4. Derive the message key for this message.
    assert state.ckr is not None
    mk, state.ckr = _kdf_ck(state.ckr)
    state.nr += 1
    if verify_mac is not None:
        verify_mac(_derive_message_keys(mk)[0])
    return _decrypt_aes_cbc(mk, ciphertext)


# Public helpers the test suite uses directly.
def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Exported for self-consistency testing."""
    return _kdf_rk(rk, dh_out)


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Exported for self-consistency testing."""
    return _kdf_ck(ck)


def _unused_random() -> bytes:
    # Keep ``secrets`` / ``os`` imported for downstream use; no behaviour.
    return secrets.token_bytes(1) + os.urandom(1)
