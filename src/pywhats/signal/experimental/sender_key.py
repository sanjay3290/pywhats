# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Signal group (sender-key) session — encrypt/decrypt group ``skmsg`` (issue #39).

WhatsApp groups use the libsignal *sender key* construction rather than
pairwise Double Ratchet: each member has one sending session (a symmetric
hash-ratchet chain key plus a signing key pair). The member distributes
the chain key + signing public key once, in a
``SenderKeyDistributionMessage`` fanned out over the existing 1:1 Signal
sessions; thereafter every group message is a single ``skmsg`` encrypted
under the current chain key and signed, so it can be delivered to all
members at once.

Mirrors libsignal ``groups`` (SenderKeyState / SenderChainKey /
SenderMessageKey / GroupCipher / GroupSessionBuilder):

* chain-key ratchet — ``msgKeySeed = HMAC-SHA256(chainKey, 0x01)``,
  ``nextChainKey = HMAC-SHA256(chainKey, 0x02)``;
* message key — ``HKDF(msgKeySeed, "WhisperGroup", 48)`` → iv || cipherKey;
* ``skmsg`` = ``0x33 || SenderKeyMessage`` protobuf ``|| XEdDSA sig`` over
  those bytes with the sender's signing key.

**Clean-room and UNAUDITED** (see ``SECURITY.md``) — like the rest of
``pywhats.signal.experimental``. Not validated against a live group yet.
"""

from __future__ import annotations

import hmac as _hmac
import secrets
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pywhats.proto import SenderKeyDistributionMessageBody, SenderKeyMessageBody
from pywhats.signal.experimental.keys import signal_pubkey, xeddsa_sign, xeddsa_verify
from pywhats.socket.crypto import generate_keypair

__all__ = [
    "SenderKeyState",
    "SenderKeyError",
    "InvalidSenderKeySignature",
    "create_sender_key_state",
    "build_distribution_message",
    "process_distribution_message",
    "group_encrypt",
    "group_decrypt",
    "serialize_sender_key_state",
    "deserialize_sender_key_state",
    "SenderKeyStore",
    "InMemorySenderKeyStore",
]

_VERSION = 3
_VERSION_BYTE = bytes([(_VERSION << 4) | _VERSION])  # 0x33
_MSG_SEED = b"\x01"
_CHAIN_SEED = b"\x02"
_WHISPER_GROUP = b"WhisperGroup"
_MAX_JUMP = 2000  # libsignal's skipped-key ceiling


class SenderKeyError(Exception):
    """Base for sender-key session failures."""


class InvalidSenderKeySignature(SenderKeyError):
    """The ``skmsg`` signature did not verify under the sender's key."""


@dataclass(frozen=True)
class SenderKeyState:
    """One sender-key session: the ratchet chain + signing key pair.

    ``signing_private`` is set only for our own sending state; a state
    built from a peer's distribution message has it ``None`` (verify-only).
    """

    key_id: int
    iteration: int
    chain_key: bytes
    signing_public: bytes  # raw 32-byte X25519 public
    signing_private: bytes | None = None


def _hmac256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, sha256).digest()


def _message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """Derive (iv, cipher_key) for the current chain key (libsignal SenderMessageKey)."""
    seed = _hmac256(chain_key, _MSG_SEED)
    derivative = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=_WHISPER_GROUP).derive(
        seed
    )
    return derivative[:16], derivative[16:48]


def _next_chain_key(chain_key: bytes) -> bytes:
    return _hmac256(chain_key, _CHAIN_SEED)


def create_sender_key_state(key_id: int) -> SenderKeyState:
    """Create a fresh own sending session (random chain key + signing key pair)."""
    signing_private, signing_public = generate_keypair()
    chain_key = secrets.token_bytes(32)  # full 256-bit random initial chain seed
    return SenderKeyState(
        key_id=key_id,
        iteration=0,
        chain_key=chain_key,
        signing_public=signing_public,
        signing_private=signing_private,
    )


def build_distribution_message(state: SenderKeyState) -> bytes:
    """Serialise ``state`` as a ``SenderKeyDistributionMessage`` (0x33 || protobuf).

    These bytes go into the WAE2E ``SenderKeyDistributionMessage``'s
    ``axolotl_sender_key_distribution_message`` field for fan-out.
    """
    body = SenderKeyDistributionMessageBody(
        id=state.key_id,
        iteration=state.iteration,
        chain_key=state.chain_key,
        signing_key=signal_pubkey(state.signing_public),
    )
    return _VERSION_BYTE + bytes(body.SerializeToString())


def process_distribution_message(data: bytes) -> SenderKeyState:
    """Parse a peer's distribution message into a verify-only receiving state."""
    body = SenderKeyDistributionMessageBody()
    body.ParseFromString(data[1:])  # strip the version byte
    return SenderKeyState(
        key_id=int(body.id),
        iteration=int(body.iteration),
        chain_key=bytes(body.chain_key),
        signing_public=_strip_djb(bytes(body.signing_key)),
        signing_private=None,
    )


def group_encrypt(state: SenderKeyState, plaintext: bytes) -> tuple[bytes, SenderKeyState]:
    """Encrypt a group message under the current chain key; return (skmsg, advanced state)."""
    if state.signing_private is None:
        raise SenderKeyError("cannot encrypt without a signing private key")
    iv, cipher_key = _message_key(state.chain_key)
    ciphertext = _aes_cbc_encrypt(cipher_key, iv, plaintext)
    skmsg = _build_skmsg(state.key_id, state.iteration, ciphertext, state.signing_private)
    advanced = replace(
        state, iteration=state.iteration + 1, chain_key=_next_chain_key(state.chain_key)
    )
    return skmsg, advanced


def group_decrypt(state: SenderKeyState, skmsg: bytes) -> tuple[bytes, SenderKeyState]:
    """Verify + decrypt a group ``skmsg``; return (plaintext, advanced state).

    The chain is fast-forwarded to the message's iteration (bounded by
    ``_MAX_JUMP``). Skipped keys are not cached, so out-of-order delivery
    within a chain is not yet supported.
    """
    if len(skmsg) < 64:
        raise SenderKeyError("skmsg too short")
    serialized, signature = skmsg[:-64], skmsg[-64:]
    if not xeddsa_verify(state.signing_public, serialized, signature):
        raise InvalidSenderKeySignature("skmsg signature did not verify")

    body = SenderKeyMessageBody()
    body.ParseFromString(serialized[1:])  # strip version byte
    target = int(body.iteration)
    if target < state.iteration:
        raise SenderKeyError(
            f"skmsg iteration {target} is older than chain iteration {state.iteration}"
        )
    if target - state.iteration > _MAX_JUMP:
        raise SenderKeyError(f"skmsg iteration jump too large: {target - state.iteration}")

    chain_key = state.chain_key
    iteration = state.iteration
    while iteration < target:
        chain_key = _next_chain_key(chain_key)
        iteration += 1

    iv, cipher_key = _message_key(chain_key)
    plaintext = _aes_cbc_decrypt(cipher_key, iv, bytes(body.ciphertext))
    advanced = replace(state, iteration=iteration + 1, chain_key=_next_chain_key(chain_key))
    return plaintext, advanced


def serialize_sender_key_state(state: SenderKeyState) -> dict[str, object]:
    """JSON-friendly representation for persistence (keys hex-encoded)."""
    return {
        "key_id": state.key_id,
        "iteration": state.iteration,
        "chain_key": state.chain_key.hex(),
        "signing_public": state.signing_public.hex(),
        "signing_private": state.signing_private.hex() if state.signing_private else None,
    }


def deserialize_sender_key_state(data: dict[str, object]) -> SenderKeyState:
    sp = data["signing_private"]
    key_id = data["key_id"]
    iteration = data["iteration"]
    chain_key = data["chain_key"]
    signing_public = data["signing_public"]
    assert isinstance(key_id, int)
    assert isinstance(iteration, int)
    assert isinstance(chain_key, str)
    assert isinstance(signing_public, str)
    return SenderKeyState(
        key_id=key_id,
        iteration=iteration,
        chain_key=bytes.fromhex(chain_key),
        signing_public=bytes.fromhex(signing_public),
        signing_private=bytes.fromhex(sp) if isinstance(sp, str) else None,
    )


def _build_skmsg(key_id: int, iteration: int, ciphertext: bytes, signing_private: bytes) -> bytes:
    body = SenderKeyMessageBody(id=key_id, iteration=iteration, ciphertext=ciphertext)
    serialized = _VERSION_BYTE + bytes(body.SerializeToString())
    signature = xeddsa_sign(signing_private, serialized)
    return serialized + signature


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise SenderKeyError("skmsg ciphertext is not a block multiple")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 16 or pad > len(padded) or padded[-pad:] != bytes([pad]) * pad:
        raise SenderKeyError("invalid PKCS#7 padding in skmsg")
    return padded[:-pad]


def _strip_djb(public: bytes) -> bytes:
    if len(public) == 33 and public[0] == 0x05:
        return public[1:]
    if len(public) == 32:
        return public
    raise SenderKeyError(f"invalid signing key length {len(public)}")


class SenderKeyStore(Protocol):
    """Persistence for sender-key sessions, keyed by (group, sender address)."""

    def load(self, group_id: str, sender_id: str) -> SenderKeyState | None: ...

    def save(self, group_id: str, sender_id: str, state: SenderKeyState) -> None: ...

    def delete(self, group_id: str, sender_id: str) -> None: ...


class InMemorySenderKeyStore:
    """Volatile :class:`SenderKeyStore` for tests and pathless clients."""

    def __init__(self) -> None:
        self._states: dict[tuple[str, str], SenderKeyState] = {}

    def load(self, group_id: str, sender_id: str) -> SenderKeyState | None:
        return self._states.get((group_id, sender_id))

    def save(self, group_id: str, sender_id: str, state: SenderKeyState) -> None:
        self._states[(group_id, sender_id)] = state

    def delete(self, group_id: str, sender_id: str) -> None:
        self._states.pop((group_id, sender_id), None)
