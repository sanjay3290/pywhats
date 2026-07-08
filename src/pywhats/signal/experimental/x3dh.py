# SPDX-License-Identifier: Apache-2.0
"""X3DH key agreement (initiator + responder).

Spec: https://signal.org/docs/specifications/x3dh/

Implementation choices (see SECURITY.md for full list):
  - Curve: X25519.
  - Hash: SHA-256 (HKDF).
  - F prefix: 32 bytes of 0xFF (X3DH 2.1 for X25519).
  - KDF salt: 32 zero bytes (HKDF hash output length).
  - Info string: ``b"WhisperText"`` (libsignal-compatible).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pywhats.signal.experimental.keys import (
    IdentityKeyPair,
    OneTimePreKey,
    PreKeyBundle,
    SignalCryptoError,
    SignedPreKey,
)

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)


# X3DH 2.1: F = 32 0xFF bytes when using X25519.
_X3DH_F: Final[bytes] = b"\xff" * 32
X3DH_INFO: Final[bytes] = b"WhisperText"


def _dh(private: bytes, peer_public: bytes) -> bytes:
    if len(private) != 32 or len(peer_public) != 32:
        raise SignalCryptoError("invalid key length for DH")
    sk = X25519PrivateKey.from_private_bytes(private)
    pk = X25519PublicKey.from_public_bytes(peer_public)
    return sk.exchange(pk)


def _kdf(ikm: bytes, info: bytes) -> bytes:
    """X3DH 2.2 KDF: HKDF(salt=zeros(32), ikm=F||KM, info=info, L=32)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info)
    return hkdf.derive(_X3DH_F + ikm)


@dataclass(frozen=True)
class X3DHInitiatorResult:
    shared_secret: bytes  # 32 bytes
    associated_data: bytes  # AD = IKA_pub || IKB_pub
    ephemeral_public: bytes  # EKA public
    identity_public: bytes  # IKA public
    used_signed_pre_key_id: int
    used_one_time_pre_key_id: int | None


@dataclass(frozen=True)
class X3DHResponderResult:
    shared_secret: bytes
    associated_data: bytes


def x3dh_initiator(
    identity: IdentityKeyPair,
    peer_bundle: PreKeyBundle,
    ephemeral: IdentityKeyPair | None = None,
) -> X3DHInitiatorResult:
    """X3DH 3.2: initiator (Alice) side.

    Verifies the signed prekey signature, performs the three or four
    DH computations, derives SK via HKDF, and returns the bundle of data
    the initiator needs to send in the initial message.
    """
    # X3DH 3.2 step 1: verify signed prekey signature.
    if not peer_bundle.verify_signature():
        raise SignalCryptoError("signed prekey signature verification failed")

    # X3DH 3.2 step 2: generate ephemeral key pair EKA.
    if ephemeral is None:
        ephemeral = IdentityKeyPair.generate()

    # X3DH 3.2 step 3: DH1..DH4.
    dh1 = _dh(identity.private, peer_bundle.signed_pre_key_public)  # DH(IKA, SPKB)
    dh2 = _dh(ephemeral.private, peer_bundle.identity_key)  # DH(EKA, IKB)
    dh3 = _dh(ephemeral.private, peer_bundle.signed_pre_key_public)  # DH(EKA, SPKB)
    km = dh1 + dh2 + dh3
    if peer_bundle.one_time_pre_key_public is not None:
        km += _dh(ephemeral.private, peer_bundle.one_time_pre_key_public)

    sk = _kdf(km, X3DH_INFO)
    # X3DH 3.3: AD = Encode(IKA) || Encode(IKB). For X25519, Encode is the
    # raw 32-byte public key.
    ad = identity.public + peer_bundle.identity_key

    # Wipe intermediates.
    _wipe(km)
    _wipe(dh1)
    _wipe(dh2)
    _wipe(dh3)

    return X3DHInitiatorResult(
        shared_secret=sk,
        associated_data=ad,
        ephemeral_public=ephemeral.public,
        identity_public=identity.public,
        used_signed_pre_key_id=peer_bundle.signed_pre_key_id,
        used_one_time_pre_key_id=peer_bundle.one_time_pre_key_id,
    )


def x3dh_responder(
    identity: IdentityKeyPair,
    signed_pre_key: SignedPreKey,
    one_time_pre_key: OneTimePreKey | None,
    initiator_identity_public: bytes,
    initiator_ephemeral_public: bytes,
) -> X3DHResponderResult:
    """X3DH 3.3: responder (Bob) side.

    Recomputes DH1..DH4 from the initiator's published IKA and EKA and
    returns the same shared secret / AD the initiator computed.
    """
    dh1 = _dh(signed_pre_key.private, initiator_identity_public)
    dh2 = _dh(identity.private, initiator_ephemeral_public)
    dh3 = _dh(signed_pre_key.private, initiator_ephemeral_public)
    km = dh1 + dh2 + dh3
    if one_time_pre_key is not None:
        km += _dh(one_time_pre_key.private, initiator_ephemeral_public)

    sk = _kdf(km, X3DH_INFO)
    ad = initiator_identity_public + identity.public

    _wipe(km)
    _wipe(dh1)
    _wipe(dh2)
    _wipe(dh3)

    return X3DHResponderResult(shared_secret=sk, associated_data=ad)


def _wipe(b: bytes) -> None:
    """Best-effort zeroisation for a bytes value (no guarantees in CPython)."""
    # bytes are immutable; the best we can do is drop references. Callers
    # that need stronger guarantees should use bytearray themselves.
    del b
