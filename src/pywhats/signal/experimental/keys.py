# SPDX-License-Identifier: Apache-2.0
"""Key pair types and XEdDSA signing for the experimental Signal impl.

Spec references:
  - XEdDSA:  https://signal.org/docs/specifications/xeddsa/
  - X3DH 2.4 "Identity keys" / "Signed prekey".
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import warnings
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from pywhats.errors import PyWhatsError
from pywhats.signal.experimental import _ed25519 as ed

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)


class SignalCryptoError(PyWhatsError):
    """Generic cryptographic failure in the experimental Signal impl.

    Messages are intentionally vague; no key material or plaintext is
    included in the text.
    """


# XEdDSA "hash1" domain separation prefix for Curve25519 (XEdDSA spec 2.2).
# hash1(x) = SHA-512(0xFE || 0xFF*31 || x).
_XEDDSA_HASH1_PREFIX: Final[bytes] = b"\xfe" + b"\xff" * 31


def _x25519_raw_private(k: X25519PrivateKey) -> bytes:
    return k.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _x25519_raw_public(k: X25519PublicKey) -> bytes:
    return k.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _calc_ed_keypair(k_scalar: int) -> tuple[bytes, int]:
    """XEdDSA calculate_key_pair: derive an Ed25519 signing pair from X25519.

    Returns ``(A_compressed, a_scalar)`` where ``A`` always has sign bit 0.
    """
    # E = kB
    E = ed.scalar_mult_base(k_scalar)
    E_enc = ed.encode_point(E)
    sign_bit = (E_enc[31] >> 7) & 1
    a = (-k_scalar) % ed.q if sign_bit == 1 else k_scalar % ed.q
    # Clear the sign bit on A
    A_bytes = bytearray(E_enc)
    A_bytes[31] &= 0x7F
    return bytes(A_bytes), a


def xeddsa_sign(x25519_private: bytes, message: bytes, random_z: bytes | None = None) -> bytes:
    """XEdDSA signature over ``message`` using an X25519 private key.

    Spec: XEdDSA 2.4 ``xeddsa_sign``.
    """
    if len(x25519_private) != 32:
        raise SignalCryptoError("invalid private key length")
    if random_z is None:
        random_z = secrets.token_bytes(64)
    if len(random_z) != 64:
        raise SignalCryptoError("invalid xeddsa nonce length")

    k_scalar = ed.clamp_scalar(x25519_private)
    A, a = _calc_ed_keypair(k_scalar)
    a_bytes = int.to_bytes(a, 32, "little")

    # r = hash1(a || M || Z) (mod q)
    r = (
        int.from_bytes(
            hashlib.sha512(_XEDDSA_HASH1_PREFIX + a_bytes + message + random_z).digest(),
            "little",
        )
        % ed.q
    )
    # R = rB
    R = ed.scalar_mult_base(r)
    R_enc = ed.encode_point(R)
    # h = hash(R || A || M) (mod q) -- plain SHA-512 (XEdDSA spec 2.2).
    h = int.from_bytes(hashlib.sha512(R_enc + A + message).digest(), "little") % ed.q
    s = (r + h * a) % ed.q
    return R_enc + int.to_bytes(s, 32, "little")


def xeddsa_verify(x25519_public: bytes, message: bytes, signature: bytes) -> bool:
    """libsignal-compatible XEdDSA verification.

    Accepts signatures produced by:
      * spec-style XEdDSA (``A.sign`` forced to 0, scalar ``s`` fills the
        last 32 bytes)
      * libsignal's compatibility variant where the high bit of the final
        signature byte carries the Edwards sign bit for ``A``, and ``s``
        occupies the low 255 bits

    WhatsApp's server-generated signed-prekey signatures are the
    libsignal variant, so a spec-only verifier rejects them even though
    the math is correct. See GPT Pro diagnosis in commit message.
    """
    if len(x25519_public) != 32 or len(signature) != 64:
        return False
    u = int.from_bytes(x25519_public, "little") & ((1 << 255) - 1)
    if u >= ed.p:
        return False

    R_bytes = signature[:32]
    s_bytes = bytearray(signature[32:])
    # Strip the libsignal-style embedded ``A`` sign bit out of ``s`` before
    # parsing it as a scalar.
    a_sign_bit = (s_bytes[31] >> 7) & 1
    s_bytes[31] &= 0x7F
    # Even after masking the sign bit, ``s`` should fit within a
    # 255-bit scalar; libsignal rejects anything with the next two bits
    # set. This is stricter than ``s < q`` and matches libsignal's check.
    if (s_bytes[31] & 0xE0) != 0:
        return False
    s = int.from_bytes(s_bytes, "little") % ed.q

    # Reconstruct ``A`` from the Montgomery u with the sign bit that came
    # out of the signature.
    y = ed.mont_u_to_ed_y(u)
    A_bytes_mut = bytearray(int.to_bytes(y, 32, "little"))
    A_bytes_mut[31] |= a_sign_bit << 7
    A_bytes = bytes(A_bytes_mut)

    A = ed.decode_point(A_bytes)
    if A is None:
        return False
    R = ed.decode_point(R_bytes)
    if R is None:
        return False

    h = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + message).digest(), "little") % ed.q
    sB = ed.scalar_mult_base(s)
    hA = ed._scalar_mult(h, A)
    Rcheck = ed.point_add(sB, ed.point_negate(hA))
    return hmac.compare_digest(R_bytes, ed.encode_point(Rcheck))


@dataclass(frozen=True)
class IdentityKeyPair:
    """Long-term X25519 identity key pair.

    Used for both DH (in X3DH) and XEdDSA signatures over prekeys.
    """

    private: bytes  # 32 raw bytes
    public: bytes  # 32 raw bytes

    @classmethod
    def generate(cls) -> IdentityKeyPair:
        sk = X25519PrivateKey.generate()
        return cls(private=_x25519_raw_private(sk), public=_x25519_raw_public(sk.public_key()))

    def dh(self, peer_public: bytes) -> bytes:
        if len(peer_public) != 32:
            raise SignalCryptoError("invalid peer public key length")
        sk = X25519PrivateKey.from_private_bytes(self.private)
        pk = X25519PublicKey.from_public_bytes(peer_public)
        return sk.exchange(pk)

    def sign(self, message: bytes) -> bytes:
        return xeddsa_sign(self.private, message)


_SIGNAL_KEY_TYPE = b"\x05"


def signal_pubkey(raw_public: bytes) -> bytes:
    """Return the Signal-encoded form of a 32-byte Curve25519 public key.

    libsignal treats a public key as ``type_byte || raw_32_bytes`` (type
    0x05 for Curve25519). XEdDSA signatures covering a "public key" must
    sign that 33-byte form, not the raw 32 bytes — a subtle divergence
    from a naive X3DH read-through.
    """
    if len(raw_public) == 33:
        if raw_public[0] != 0x05:
            raise SignalCryptoError("invalid Signal public key type byte")
        return raw_public
    if len(raw_public) != 32:
        raise SignalCryptoError("invalid raw public key length")
    return _SIGNAL_KEY_TYPE + raw_public


@dataclass(frozen=True)
class SignedPreKey:
    """Signed prekey with a stable identifier. Spec: X3DH 2.4."""

    key_id: int
    private: bytes
    public: bytes
    signature: bytes  # XEdDSA signature by identity over signal_pubkey(public)

    @classmethod
    def generate(cls, identity: IdentityKeyPair, key_id: int) -> SignedPreKey:
        sk = X25519PrivateKey.generate()
        pub = _x25519_raw_public(sk.public_key())
        priv = _x25519_raw_private(sk)
        # Sign the Signal-encoded (type-byte-prefixed) public key — that's
        # what libsignal verifies on the peer side.
        sig = identity.sign(signal_pubkey(pub))
        return cls(key_id=key_id, private=priv, public=pub, signature=sig)

    def verify(self, identity_public: bytes) -> bool:
        return xeddsa_verify(identity_public, signal_pubkey(self.public), self.signature)


@dataclass(frozen=True)
class OneTimePreKey:
    """Unsigned one-time prekey (OPK). Spec: X3DH 2.4."""

    key_id: int
    private: bytes
    public: bytes


def generate_pre_key(key_id: int) -> OneTimePreKey:
    sk = X25519PrivateKey.generate()
    return OneTimePreKey(
        key_id=key_id,
        private=_x25519_raw_private(sk),
        public=_x25519_raw_public(sk.public_key()),
    )


@dataclass(frozen=True)
class PreKeyBundle:
    """Responder-published bundle fetched by the initiator. Spec: X3DH 3.1."""

    identity_key: bytes  # IKB public
    signed_pre_key_id: int
    signed_pre_key_public: bytes  # SPKB public
    signed_pre_key_signature: bytes  # Sig(IKB, SPKB)
    one_time_pre_key_id: int | None = None
    one_time_pre_key_public: bytes | None = None  # OPKB public (optional)

    def verify_signature(self) -> bool:
        return xeddsa_verify(
            self.identity_key,
            signal_pubkey(self.signed_pre_key_public),
            self.signed_pre_key_signature,
        )


def secure_random(n: int) -> bytes:
    """Wrapper for clarity at call sites."""
    return os.urandom(n)
