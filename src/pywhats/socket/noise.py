# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Noise Protocol XX handshake for the WhatsApp multi-device transport.

This module implements the initiator side of the Noise_XX handshake and the
post-handshake transport cipher. The implementation follows the Noise
Protocol Framework specification (https://noiseprotocol.org/noise.html) —
each algorithmic step carries an inline reference to the relevant spec
section (5.1 CipherState, 5.2 SymmetricState, 5.3 HandshakeState, 7 for
the XX pattern tokens).

Scope:

* :class:`CipherState` — 5.1
* :class:`SymmetricState` — 5.2 (MixKey, MixHash, EncryptAndHash, DecryptAndHash, Split)
* :class:`HandshakeState` — 5.3 initiator with XX message patterns
* :class:`NoiseHandshake` — driver that wraps a framed socket (see
  ``transport.NoiseSocket``) and wire-encodes each handshake leg as a
  ``HandshakeMessage`` protobuf
* :class:`NoiseTransport` — post-handshake ``send`` / ``recv`` with
  separate send/recv counters and automatic rekey at the 2**31 mark

WhatsApp-specific protocol choices:

* Protocol name — TODO: the exact WhatsApp ciphersuite has varied across
  protocol versions between ``Noise_XX_25519_AESGCM_SHA256`` and
  ``Noise_XX_25519_ChaChaPoly_SHA256`` in public writeups. This module
  accepts either and defaults to ``Noise_XX_25519_ChaChaPoly_SHA256``
  because ChaChaPoly is the value most commonly documented for the current
  multi-device protocol. Verify against a fresh wire capture before
  production use.
* Prologue bytes — TODO: public writeups describe the prologue as
  ``b"WA"`` followed by two protocol-version bytes (seen as ``[5, 2]`` in
  several writeups). This module defaults to ``b"WA\\x05\\x02"`` but
  exposes the prologue as a constructor argument so callers can override.
  The exact version pair changes when WhatsApp bumps the protocol; this
  value has NOT been independently verified against a current wire
  capture and should be treated as unverified.

No client-source reverse engineering was performed in writing this file.
It is derived exclusively from the public Noise specification and from
prose descriptions of the handshake's observable wire shape.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag

from pywhats.errors import HandshakeError
from pywhats.proto import HandshakeMessage
from pywhats.socket.crypto import (
    DHLEN,
    HASHLEN,
    aead_decrypt,
    aead_encrypt,
    dh,
    generate_keypair,
    hash_sha256,
    hkdf,
    private_to_public,
)

__all__ = [
    "NOISE_PROTOCOL_CHACHA",
    "NOISE_PROTOCOL_AESGCM",
    "DEFAULT_PROLOGUE",
    "CipherState",
    "SymmetricState",
    "HandshakeState",
    "NoiseHandshake",
    "NoiseTransport",
]

_log = logging.getLogger("pywhats.noise")

# Noise spec 8: protocol_name = "Noise_" + pattern + "_" + DH + "_" + Cipher + "_" + Hash.
NOISE_PROTOCOL_CHACHA = b"Noise_XX_25519_ChaChaPoly_SHA256"
NOISE_PROTOCOL_AESGCM = b"Noise_XX_25519_AESGCM_SHA256"

# TODO: unverified — see module docstring.
DEFAULT_PROLOGUE = b"WA\x06\x03"  # WhatsApp "intro header": WA + version 6 + dict 3

# Noise spec 5.1: rekey nonce ceiling. The spec mandates rekey / session
# shutdown before the AEAD counter reaches 2**64-1. A much earlier rekey
# trigger of 2**31 is sensible operationally and is called out by the
# issue we are implementing.
_REKEY_INTERVAL = 1 << 31

# Length of the AEAD authentication tag in bytes for both supported ciphers.
_TAG_LEN = 16


# ---------------------------------------------------------------------------
# Section 5.1 — CipherState
# ---------------------------------------------------------------------------


class CipherState:
    """Noise spec 5.1: a key + 64-bit counter used by an AEAD cipher."""

    def __init__(self, cipher: str) -> None:
        if cipher not in ("ChaChaPoly", "AESGCM"):
            raise ValueError(f"unsupported Noise cipher: {cipher}")
        self._cipher = cipher
        # Noise spec 5.1: k is "empty" initially (represented here as None).
        self._k: bytes | None = None
        # Noise spec 5.1: n starts at 0.
        self._n: int = 0

    @property
    def cipher(self) -> str:
        return self._cipher

    def initialize_key(self, key: bytes | None) -> None:
        """Noise spec 5.1: InitializeKey(key); also resets n to 0."""
        if key is not None and len(key) != 32:
            raise ValueError("Noise CipherState key must be 32 bytes")
        self._k = key
        self._n = 0

    def has_key(self) -> bool:
        """Noise spec 5.1: HasKey() — True if k is non-empty."""
        return self._k is not None

    def set_nonce(self, nonce: int) -> None:
        """Noise spec 5.1: SetNonce(nonce)."""
        self._n = nonce

    @property
    def nonce(self) -> int:
        return self._n

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """Noise spec 5.1: EncryptWithAd(ad, plaintext)."""
        if self._k is None:
            # Noise spec 5.1: if k is empty, plaintext passes through.
            return plaintext
        ct = aead_encrypt(self._cipher, self._k, self._n, ad, plaintext)
        # Noise spec 5.1: on success, n is incremented.
        self._n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """Noise spec 5.1: DecryptWithAd(ad, ciphertext).

        Authentication failure surfaces as :class:`HandshakeError` with no
        sensitive detail in the message. Per the spec, on failure the
        nonce is NOT incremented.
        """
        if self._k is None:
            return ciphertext
        try:
            pt = aead_decrypt(self._cipher, self._k, self._n, ad, ciphertext)
        except InvalidTag as e:
            raise HandshakeError("AEAD authentication failed") from e
        self._n += 1
        return pt

    def rekey(self) -> None:
        """Noise spec 5.1: Rekey() — default REKEY encrypts 32 zero bytes
        at the max nonce and takes the first 32 bytes of the ciphertext
        as the new key. Does NOT reset the nonce.
        """
        if self._k is None:
            raise HandshakeError("cannot rekey an empty CipherState")
        zeros = b"\x00" * 32
        # Noise spec 5.1: REKEY uses maxnonce = 2**64 - 1.
        new_key_ct = aead_encrypt(self._cipher, self._k, (1 << 64) - 1, b"", zeros)
        new_k = new_key_ct[:32]
        # Best-effort zeroization of the old key.
        if isinstance(self._k, bytearray):
            for i in range(len(self._k)):
                self._k[i] = 0
        self._k = new_k


# ---------------------------------------------------------------------------
# Section 5.2 — SymmetricState
# ---------------------------------------------------------------------------


class SymmetricState:
    """Noise spec 5.2: wraps a CipherState with a chaining key ck and
    handshake hash h that evolves as tokens are processed."""

    def __init__(self, protocol_name: bytes, cipher: str) -> None:
        self._cs = CipherState(cipher)
        self._cipher = cipher
        # Noise spec 5.2: InitializeSymmetric.
        if len(protocol_name) <= HASHLEN:
            self._h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            self._h = hash_sha256(protocol_name)
        # Noise spec 5.2: ck = h.
        self._ck = self._h
        # Noise spec 5.2: InitializeKey(empty).
        self._cs.initialize_key(None)

    @property
    def handshake_hash(self) -> bytes:
        """Noise spec 5.2: GetHandshakeHash()."""
        return self._h

    @property
    def cipher(self) -> str:
        return self._cipher

    def mix_key(self, input_key_material: bytes) -> None:
        """Noise spec 5.2: MixKey — HKDF(ck, ikm, 2), re-key CipherState."""
        ck, temp_k = hkdf(self._ck, input_key_material, 2)
        # HASHLEN is 32 for SHA256, no truncation needed.
        self._ck = ck
        self._cs.initialize_key(temp_k)

    def mix_hash(self, data: bytes) -> None:
        """Noise spec 5.2: MixHash — h = HASH(h || data)."""
        self._h = hash_sha256(self._h + data)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Noise spec 5.2: EncryptAndHash(plaintext)."""
        ct = self._cs.encrypt_with_ad(self._h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Noise spec 5.2: DecryptAndHash(ciphertext).

        Note that MixHash uses the ciphertext unconditionally; per the
        spec the hash chain advances regardless of whether a key is set
        (if k is empty, ciphertext is the plaintext and the hash is
        still mixed with it).
        """
        pt = self._cs.decrypt_with_ad(self._h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        """Noise spec 5.2: Split — derive two fresh CipherStates for
        transport, keyed from HKDF(ck, zerolen, 2)."""
        temp_k1, temp_k2 = hkdf(self._ck, b"", 2)
        c1 = CipherState(self._cipher)
        c1.initialize_key(temp_k1)
        c2 = CipherState(self._cipher)
        c2.initialize_key(temp_k2)
        return c1, c2


# ---------------------------------------------------------------------------
# Section 5.3 — HandshakeState (initiator, XX pattern only)
# ---------------------------------------------------------------------------

# Noise spec 7.4: pattern XX = { -> e ; <- e, ee, s, es ; -> s, se }
_XX_INITIATOR_MESSAGES: tuple[tuple[str, ...], ...] = (
    ("e",),
    ("e", "ee", "s", "es"),
    ("s", "se"),
)


@dataclass
class _Keypair:
    private: bytes
    public: bytes


class HandshakeState:
    """Noise spec 5.3: initiator-side HandshakeState for the XX pattern."""

    def __init__(
        self,
        protocol_name: bytes,
        cipher: str,
        prologue: bytes,
        local_static_private: bytes,
    ) -> None:
        # Noise spec 5.3: InitializeSymmetric, MixHash(prologue).
        self._ss = SymmetricState(protocol_name, cipher)
        self._ss.mix_hash(prologue)
        # Initiator is always "true" here; XX has no pre-messages.
        self._s = _Keypair(local_static_private, private_to_public(local_static_private))
        self._e: _Keypair | None = None
        # Remote ephemeral / static once learned.
        self._re: bytes | None = None
        self._rs: bytes | None = None
        # Remaining message patterns — consumed one per WriteMessage / ReadMessage.
        self._messages: list[tuple[str, ...]] = list(_XX_INITIATOR_MESSAGES)

    @property
    def handshake_hash(self) -> bytes:
        return self._ss.handshake_hash

    @property
    def finished(self) -> bool:
        return not self._messages

    # ---- token helpers ---------------------------------------------------

    def _dh_es(self) -> bytes:
        # Noise spec 5.3 (initiator): es -> DH(e, rs).
        assert self._e is not None and self._rs is not None
        return dh(self._e.private, self._rs)

    def _dh_se(self) -> bytes:
        # Noise spec 5.3 (initiator): se -> DH(s, re).
        assert self._re is not None
        return dh(self._s.private, self._re)

    def _dh_ee(self) -> bytes:
        assert self._e is not None and self._re is not None
        return dh(self._e.private, self._re)

    # ---- WriteMessage / ReadMessage -------------------------------------

    def write_message(
        self, payload: bytes, *, ephemeral_private: bytes | None = None
    ) -> tuple[bytes, tuple[CipherState, CipherState] | None]:
        """Noise spec 5.3: WriteMessage — returns (wire_bytes, split_or_None).

        ``ephemeral_private`` is a test hook to inject a known ephemeral
        keypair (for reproducing published Noise test vectors). Production
        code leaves it ``None`` so a fresh random key is used.
        """
        if not self._messages:
            raise HandshakeError("handshake already finished")
        tokens = self._messages.pop(0)
        out = bytearray()

        for token in tokens:
            if token == "e":
                # Noise spec 5.3: e = GENERATE_KEYPAIR; append e.pub; MixHash(e.pub).
                if ephemeral_private is not None:
                    priv = ephemeral_private
                    pub = private_to_public(priv)
                else:
                    priv, pub = generate_keypair()
                self._e = _Keypair(priv, pub)
                out += pub
                self._ss.mix_hash(pub)
            elif token == "s":
                # Noise spec 5.3: append EncryptAndHash(s.pub).
                out += self._ss.encrypt_and_hash(self._s.public)
            elif token == "ee":
                self._ss.mix_key(self._dh_ee())
            elif token == "es":
                self._ss.mix_key(self._dh_es())
            elif token == "se":
                self._ss.mix_key(self._dh_se())
            else:
                raise HandshakeError("unexpected token in XX write pattern")

        # Noise spec 5.3: append EncryptAndHash(payload).
        # WA deviation: skip EncryptAndHash when payload is empty AND no key
        # is set (leg 1 with no trailing payload). The WA server's Noise
        # impl does not MixHash the empty ciphertext in that case.
        if payload or self._ss._cs.has_key():
            out += self._ss.encrypt_and_hash(payload)

        split: tuple[CipherState, CipherState] | None = None
        if not self._messages:
            split = self._ss.split()
        return bytes(out), split

    def read_message(self, message: bytes) -> tuple[bytes, tuple[CipherState, CipherState] | None]:
        """Noise spec 5.3: ReadMessage — returns (payload_bytes, split_or_None)."""
        if not self._messages:
            raise HandshakeError("handshake already finished")
        tokens = self._messages.pop(0)
        offset = 0

        for token in tokens:
            if token == "e":
                # Noise spec 5.3: re = next DHLEN bytes; MixHash(re).
                if len(message) - offset < DHLEN:
                    raise HandshakeError("handshake message truncated at ephemeral")
                self._re = message[offset : offset + DHLEN]
                offset += DHLEN
                self._ss.mix_hash(self._re)
            elif token == "s":
                # Noise spec 5.3: read DHLEN + 16 if HasKey else DHLEN; rs = DecryptAndHash.
                have_key = self._ss._cs.has_key()
                need = DHLEN + (_TAG_LEN if have_key else 0)
                if len(message) - offset < need:
                    raise HandshakeError("handshake message truncated at static")
                chunk = message[offset : offset + need]
                offset += need
                self._rs = self._ss.decrypt_and_hash(chunk)
                if len(self._rs) != DHLEN:
                    raise HandshakeError("remote static key has wrong length")
            elif token == "ee":
                self._ss.mix_key(self._dh_ee())
            elif token == "es":
                self._ss.mix_key(self._dh_es())
            elif token == "se":
                self._ss.mix_key(self._dh_se())
            else:
                raise HandshakeError("unexpected token in XX read pattern")

        # Noise spec 5.3: remaining bytes are the encrypted payload.
        # WA deviation (see write_message): skip DecryptAndHash when no key
        # is set AND no trailing bytes remain.
        remaining = message[offset:]
        if remaining or self._ss._cs.has_key():
            payload = self._ss.decrypt_and_hash(remaining)
        else:
            payload = b""

        split: tuple[CipherState, CipherState] | None = None
        if not self._messages:
            split = self._ss.split()
        return payload, split

    @property
    def remote_static(self) -> bytes | None:
        return self._rs


# ---------------------------------------------------------------------------
# Transport binding
# ---------------------------------------------------------------------------


class _FrameChannel(Protocol):
    """Minimal interface the handshake needs from the underlying socket."""

    async def send_frame(self, payload: bytes) -> None: ...
    async def recv_frame(self) -> bytes: ...


class NoiseTransport:
    """Post-handshake encrypted transport.

    Wraps a frame channel with two independent :class:`CipherState`
    objects (send / recv), each with its own 64-bit counter. Rekey is
    performed automatically after :data:`_REKEY_INTERVAL` messages on
    either side as a precaution against very long-lived sessions.
    """

    def __init__(
        self,
        channel: _FrameChannel,
        send_state: CipherState,
        recv_state: CipherState,
        handshake_hash: bytes,
    ) -> None:
        self._channel = channel
        self._send = send_state
        self._recv = recv_state
        self._h = handshake_hash
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()

    @property
    def handshake_hash(self) -> bytes:
        """Noise spec 5.2 GetHandshakeHash — exposed for channel binding."""
        return self._h

    async def send(self, plaintext: bytes) -> None:
        async with self._send_lock:
            if self._send.nonce >= _REKEY_INTERVAL:
                self._send.rekey()
                self._send.set_nonce(0)
            ct = self._send.encrypt_with_ad(b"", plaintext)
            await self._channel.send_frame(ct)

    async def recv(self) -> bytes:
        async with self._recv_lock:
            if self._recv.nonce >= _REKEY_INTERVAL:
                self._recv.rekey()
                self._recv.set_nonce(0)
            frame = await self._channel.recv_frame()
            return self._recv.decrypt_with_ad(b"", frame)


class NoiseHandshake:
    """Drive the XX handshake over a framed socket.

    The wire format on each leg is a :class:`pywhats.proto.HandshakeMessage`
    whose ``client_hello`` / ``server_hello`` /
    ``client_finish`` sub-messages carry the raw Noise bytes split into
    ``ephemeral``, ``static``, and ``payload`` fields. Only the WhatsApp
    protobuf envelope is WhatsApp-specific; the cryptographic transcript
    handled by :class:`HandshakeState` is pure Noise.
    """

    def __init__(
        self,
        channel: _FrameChannel,
        *,
        client_static_private: bytes,
        prologue: bytes = DEFAULT_PROLOGUE,
        protocol_name: bytes = NOISE_PROTOCOL_AESGCM,
    ) -> None:
        if protocol_name == NOISE_PROTOCOL_CHACHA:
            cipher = "ChaChaPoly"
        elif protocol_name == NOISE_PROTOCOL_AESGCM:
            cipher = "AESGCM"
        else:
            raise ValueError(f"unsupported Noise protocol name: {protocol_name!r}")
        self._channel = channel
        self._state = HandshakeState(
            protocol_name=protocol_name,
            cipher=cipher,
            prologue=prologue,
            local_static_private=client_static_private,
        )

    async def perform(self, client_payload: bytes) -> NoiseTransport:
        """Run the full XX handshake and return an encrypted transport.

        On any protocol / authentication error, raises
        :class:`HandshakeError` with no sensitive information in the
        message.
        """
        try:
            # --- Leg 1: -> e ---------------------------------------------
            leg1_bytes, split = self._state.write_message(b"")
            if split is not None:  # XX never splits on leg 1
                raise HandshakeError("unexpected handshake completion on leg 1")
            frame = HandshakeMessage(
                client_hello=HandshakeMessage.ClientHello(
                    ephemeral=leg1_bytes[:DHLEN],
                ),
            )
            await self._channel.send_frame(frame.SerializeToString())

            # --- Leg 2: <- e, ee, s, es ----------------------------------
            resp_bytes = await self._channel.recv_frame()
            resp = HandshakeMessage()
            try:
                resp.ParseFromString(resp_bytes)
            except Exception as e:  # noqa: BLE001 — protobuf can raise many types
                raise HandshakeError("invalid handshake response framing") from e
            server_hello = resp.server_hello
            if not server_hello.ephemeral:
                raise HandshakeError("server_hello missing ephemeral")
            leg2_wire = server_hello.ephemeral + server_hello.static + server_hello.payload
            server_payload, split = self._state.read_message(leg2_wire)
            if split is not None:
                raise HandshakeError("unexpected handshake completion on leg 2")
            _ = server_payload  # exposed to caller via transport if needed later

            # --- Leg 3: -> s, se + encrypted client payload -------------
            leg3_bytes, split = self._state.write_message(client_payload)
            if split is None:
                raise HandshakeError("handshake did not complete on leg 3")
            # Layout of leg 3: EncryptAndHash(s.pub) (DHLEN+16) || EncryptAndHash(payload)
            static_len = DHLEN + _TAG_LEN
            enc_static = leg3_bytes[:static_len]
            enc_payload = leg3_bytes[static_len:]
            finish = HandshakeMessage(
                client_finish=HandshakeMessage.ClientFinish(
                    static=enc_static,
                    payload=enc_payload,
                ),
            )
            await self._channel.send_frame(finish.SerializeToString())
        except HandshakeError:
            raise
        except Exception as e:  # noqa: BLE001
            # Do not leak transcript state into the error message.
            _log.debug("handshake failed (transport / protobuf error)")
            raise HandshakeError("handshake failed") from e

        c1, c2 = split
        # Noise spec 5.2: for an initiator, c1 is send, c2 is recv.
        return NoiseTransport(self._channel, c1, c2, self._state.handshake_hash)
