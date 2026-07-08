# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Noise primitives and a full XX spec test vector."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from pywhats.socket.crypto import (
    aead_decrypt,
    aead_encrypt,
    build_nonce_aesgcm,
    build_nonce_chachapoly,
    dh,
    generate_keypair,
    hash_sha256,
    hkdf,
    hmac_sha256,
    private_to_public,
)
from pywhats.socket.noise import (
    NOISE_PROTOCOL_CHACHA,
    CipherState,
    HandshakeState,
)


def test_nonce_encoding_chachapoly() -> None:
    assert build_nonce_chachapoly(0) == b"\x00" * 12
    # ChaChaPoly: 32 zero bits || little-endian(counter)
    assert build_nonce_chachapoly(1) == b"\x00\x00\x00\x00" + b"\x01" + b"\x00" * 7


def test_nonce_encoding_aesgcm() -> None:
    assert build_nonce_aesgcm(0) == b"\x00" * 12
    # AESGCM: 32 zero bits || big-endian(counter)
    assert build_nonce_aesgcm(1) == b"\x00\x00\x00\x00" + b"\x00" * 7 + b"\x01"


def test_hash_matches_sha256() -> None:
    import hashlib

    assert hash_sha256(b"abc") == hashlib.sha256(b"abc").digest()


def test_hmac_sha256_rfc4231_vector() -> None:
    # RFC 4231 test case 1.
    key = b"\x0b" * 20
    data = b"Hi There"
    want = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    assert hmac_sha256(key, data) == want


def test_hkdf_two_and_three_outputs() -> None:
    ck = b"\x00" * 32
    ikm = b"\x01" * 32
    a, b = hkdf(ck, ikm, 2)
    assert len(a) == 32 and len(b) == 32
    a2, b2, c2 = hkdf(ck, ikm, 3)
    # First two outputs must be identical for the same inputs.
    assert a == a2
    assert b == b2
    assert len(c2) == 32


def test_hkdf_bad_num_outputs() -> None:
    with pytest.raises(ValueError):
        hkdf(b"\x00" * 32, b"", 1)
    with pytest.raises(ValueError):
        hkdf(b"\x00" * 32, b"", 4)


def test_x25519_dh_agreement() -> None:
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    assert dh(priv_a, pub_b) == dh(priv_b, pub_a)


def test_private_to_public_stable() -> None:
    priv, pub = generate_keypair()
    assert private_to_public(priv) == pub


def test_aead_chachapoly_roundtrip_and_tamper() -> None:
    key = b"\x11" * 32
    ct = aead_encrypt("ChaChaPoly", key, 0, b"ad", b"hello")
    assert aead_decrypt("ChaChaPoly", key, 0, b"ad", ct) == b"hello"
    # Wrong nonce counter should fail authentication.
    with pytest.raises(InvalidTag):
        aead_decrypt("ChaChaPoly", key, 1, b"ad", ct)
    # Wrong associated data should fail.
    with pytest.raises(InvalidTag):
        aead_decrypt("ChaChaPoly", key, 0, b"bad", ct)


def test_aead_aesgcm_roundtrip() -> None:
    key = b"\x22" * 32
    ct = aead_encrypt("AESGCM", key, 7, b"", b"payload")
    assert aead_decrypt("AESGCM", key, 7, b"", ct) == b"payload"


# ---------------------------------------------------------------------------
# Full Noise_XX_25519_ChaChaPoly_SHA256 test vector from the public
# Cacophony vector set (also reproduced in other Noise conformance suites).
# Source: rweather/noise-c test vectors — a widely mirrored corpus used by
# multiple independent Noise implementations for interop verification.
# ---------------------------------------------------------------------------


_VEC_PROLOGUE = bytes.fromhex("4a6f686e2047616c74")
_VEC_INIT_STATIC = bytes.fromhex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
_VEC_INIT_EPHEMERAL = bytes.fromhex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
)
_VEC_RESP_STATIC = bytes.fromhex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
_VEC_RESP_EPHEMERAL = bytes.fromhex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
)

_VEC_MESSAGES = [
    (
        bytes.fromhex("4c756477696720766f6e204d69736573"),
        bytes.fromhex(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c"
            "756477696720766f6e204d69736573"
        ),
    ),
    (
        bytes.fromhex("4d757272617920526f746862617264"),
        bytes.fromhex(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381"
            "cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5"
            "269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814"
            "c7194e83f23dbd8d162c9326ad"
        ),
    ),
    (
        bytes.fromhex("462e20412e20486179656b"),
        bytes.fromhex(
            "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80a"
            "e475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae7"
            "69a1d95941d49b25030"
        ),
    ),
    (
        bytes.fromhex("4361726c204d656e676572"),
        bytes.fromhex("96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df"),
    ),
    (
        bytes.fromhex("4a65616e2d426170746973746520536179"),
        bytes.fromhex("3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5"),
    ),
    (
        bytes.fromhex("457567656e2042f6686d20766f6e2042617765726b"),
        bytes.fromhex("eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f"),
    ),
]


class _Responder:
    """Minimal responder-side XX state used only to consume the test vector.

    This mirrors the initiator-side spec logic (section 5.3) with the
    responder's token semantics for ``es`` / ``se``. It is test-only and
    lives in the test file intentionally so the production module stays
    initiator-only per scope.
    """

    def __init__(self, static_priv: bytes, ephemeral_priv: bytes, prologue: bytes) -> None:
        from pywhats.socket.noise import SymmetricState

        self._ss = SymmetricState(NOISE_PROTOCOL_CHACHA, "ChaChaPoly")
        self._ss.mix_hash(prologue)
        self._s_priv = static_priv
        self._s_pub = private_to_public(static_priv)
        self._e_priv = ephemeral_priv
        self._e_pub = private_to_public(ephemeral_priv)
        self._re: bytes | None = None
        self._rs: bytes | None = None

    def read_e(self, msg: bytes) -> bytes:
        self._re = msg[:32]
        self._ss.mix_hash(self._re)
        return self._ss.decrypt_and_hash(msg[32:])

    def write_e_ee_s_es(self, payload: bytes) -> bytes:
        out = bytearray()
        # e
        out += self._e_pub
        self._ss.mix_hash(self._e_pub)
        # ee — responder: DH(e, re)
        assert self._re is not None
        self._ss.mix_key(dh(self._e_priv, self._re))
        # s
        out += self._ss.encrypt_and_hash(self._s_pub)
        # es — responder: DH(s, re)
        self._ss.mix_key(dh(self._s_priv, self._re))
        out += self._ss.encrypt_and_hash(payload)
        return bytes(out)

    def read_s_se(self, msg: bytes) -> tuple[bytes, tuple[object, object]]:
        # s: DHLEN+16 because k is set.
        self._rs = self._ss.decrypt_and_hash(msg[: 32 + 16])
        # se — responder: DH(e, rs)
        assert self._re is not None  # not needed here but keeps types happy
        self._ss.mix_key(dh(self._e_priv, self._rs))
        payload = self._ss.decrypt_and_hash(msg[32 + 16 :])
        return payload, self._ss.split()


def test_noise_xx_chachapoly_vector_end_to_end() -> None:
    """Replay the full Noise_XX_25519_ChaChaPoly_SHA256 transcript.

    This verifies SymmetricState / HandshakeState token handling, the
    HKDF chain, and the AEAD/nonce conventions together.
    """
    initiator = HandshakeState(
        protocol_name=NOISE_PROTOCOL_CHACHA,
        cipher="ChaChaPoly",
        prologue=_VEC_PROLOGUE,
        local_static_private=_VEC_INIT_STATIC,
    )
    responder = _Responder(_VEC_RESP_STATIC, _VEC_RESP_EPHEMERAL, _VEC_PROLOGUE)

    # Leg 1 -> e
    payload, expected_ct = _VEC_MESSAGES[0]
    wire, split = initiator.write_message(payload, ephemeral_private=_VEC_INIT_EPHEMERAL)
    assert split is None
    assert wire == expected_ct
    got_payload = responder.read_e(wire)
    assert got_payload == payload

    # Leg 2 <- e, ee, s, es
    payload, expected_ct = _VEC_MESSAGES[1]
    wire = responder.write_e_ee_s_es(payload)
    assert wire == expected_ct
    got_payload, split = initiator.read_message(wire)
    assert split is None
    assert got_payload == payload

    # Leg 3 -> s, se (handshake completes with split)
    payload, expected_ct = _VEC_MESSAGES[2]
    wire, init_split = initiator.write_message(payload)
    assert init_split is not None
    assert wire == expected_ct
    got_payload, resp_split = responder.read_s_se(wire)
    assert got_payload == payload

    init_send, init_recv = init_split
    resp_recv, resp_send = resp_split  # responder's split is (c1=recv-from-init, c2=send-to-init)
    assert isinstance(init_send, CipherState)
    assert isinstance(init_recv, CipherState)
    assert isinstance(resp_recv, CipherState)
    assert isinstance(resp_send, CipherState)

    # Transport messages 4..6. In the Cacophony vector convention the
    # transport direction alternates starting with the initiator, matching
    # how the application would typically continue after leg 3.
    # Cacophony vector convention: after leg 3 the transport messages
    # alternate starting with the responder (whose "turn" comes next),
    # i.e. r2i, i2r, r2i.
    directions = ["r2i", "i2r", "r2i"]
    for idx, direction in zip((3, 4, 5), directions, strict=True):
        payload, expected_ct = _VEC_MESSAGES[idx]
        if direction == "i2r":
            ct = init_send.encrypt_with_ad(b"", payload)
            got = resp_recv.decrypt_with_ad(b"", ct)
        else:
            ct = resp_send.encrypt_with_ad(b"", payload)
            got = init_recv.decrypt_with_ad(b"", ct)
        assert ct == expected_ct, f"msg {idx} ciphertext mismatch"
        assert got == payload
