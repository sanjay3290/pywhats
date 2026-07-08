# SPDX-License-Identifier: Apache-2.0
"""Tests for the experimental Signal ratchet / X3DH / XEdDSA."""

from __future__ import annotations

import random
import warnings

import pytest

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.proto import PreKeyWhisperMessage, WhisperMessage  # noqa: E402
from pywhats.signal.experimental import (  # noqa: E402
    DEFAULT_MAX_SKIP,
    IdentityKeyPair,
    PreKeyBundle,
    PreKeySignalMessage,
    SignalMessage,
    SignedPreKey,
    generate_pre_key,
    ratchet_decrypt,
    ratchet_encrypt,
    ratchet_init_alice,
    ratchet_init_bob,
    x3dh_initiator,
    x3dh_responder,
    xeddsa_sign,
    xeddsa_verify,
)
from pywhats.signal.experimental.keys import SignalCryptoError  # noqa: E402
from pywhats.signal.experimental.ratchet import RatchetState, kdf_ck, kdf_rk  # noqa: E402
from pywhats.signal.experimental.types import MessageHeader  # noqa: E402


def _establish_session() -> tuple[RatchetState, RatchetState, bytes]:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=1)
    bob_opk = generate_pre_key(key_id=42)
    bundle = PreKeyBundle(
        identity_key=bob_ik.public,
        signed_pre_key_id=bob_spk.key_id,
        signed_pre_key_public=bob_spk.public,
        signed_pre_key_signature=bob_spk.signature,
        one_time_pre_key_id=bob_opk.key_id,
        one_time_pre_key_public=bob_opk.public,
    )
    alice_ik = IdentityKeyPair.generate()
    ar = x3dh_initiator(alice_ik, bundle)
    br = x3dh_responder(bob_ik, bob_spk, bob_opk, ar.identity_public, ar.ephemeral_public)
    assert ar.shared_secret == br.shared_secret
    assert ar.associated_data == br.associated_data
    alice = ratchet_init_alice(ar.shared_secret, bob_spk.public)
    bob = ratchet_init_bob(br.shared_secret, bob_spk.private, bob_spk.public)
    return alice, bob, ar.associated_data


def test_xeddsa_sign_verify_roundtrip() -> None:
    ik = IdentityKeyPair.generate()
    sig = xeddsa_sign(ik.private, b"hello world")
    assert len(sig) == 64
    assert xeddsa_verify(ik.public, b"hello world", sig)
    assert not xeddsa_verify(ik.public, b"hello worlD", sig)
    # tamper
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not xeddsa_verify(ik.public, b"hello world", bytes(bad))


def test_signed_pre_key_verifies() -> None:
    ik = IdentityKeyPair.generate()
    spk = SignedPreKey.generate(ik, key_id=7)
    assert spk.verify(ik.public)
    other = IdentityKeyPair.generate()
    assert not spk.verify(other.public)


def test_xeddsa_verify_accepts_libsignal_variant() -> None:
    """Regression: libsignal stores Edwards sign bit in signature[63]'s high
    bit. A spec-only verifier rejects these signatures even though the math
    is correct. Real server-produced bytes captured during send_text."""
    identity = bytes.fromhex("ffbd53759f8aaaeb172c4827700a215b0343ad3845bd8a7dcc09abeae835b829")
    spk_val = bytes.fromhex("976a91c750d9911f2839a2de9db81716118ad91ca14c3c2ee9d5760095bd5a4b")
    spk_sig = bytes.fromhex(
        "3a15a2065618006b76e40854e12c757d982f9b05a49d40d191433603e11fb6d8"
        "ac290aa5c478e2f12e6b73df529358bbb1809965f733bdc0fa12588083bde48b"
    )
    assert xeddsa_verify(identity, b"\x05" + spk_val, spk_sig)
    assert not xeddsa_verify(identity, spk_val, spk_sig)


def test_x3dh_without_opk_still_agrees() -> None:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=1)
    bundle = PreKeyBundle(
        identity_key=bob_ik.public,
        signed_pre_key_id=bob_spk.key_id,
        signed_pre_key_public=bob_spk.public,
        signed_pre_key_signature=bob_spk.signature,
    )
    alice_ik = IdentityKeyPair.generate()
    ar = x3dh_initiator(alice_ik, bundle)
    br = x3dh_responder(bob_ik, bob_spk, None, ar.identity_public, ar.ephemeral_public)
    assert ar.shared_secret == br.shared_secret


def test_x3dh_rejects_bad_signed_prekey_signature() -> None:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=1)
    tampered = bytearray(bob_spk.signature)
    tampered[0] ^= 1
    bundle = PreKeyBundle(
        identity_key=bob_ik.public,
        signed_pre_key_id=bob_spk.key_id,
        signed_pre_key_public=bob_spk.public,
        signed_pre_key_signature=bytes(tampered),
    )
    alice_ik = IdentityKeyPair.generate()
    with pytest.raises(SignalCryptoError):
        x3dh_initiator(alice_ik, bundle)


def test_kdf_ck_self_consistency() -> None:
    ck = b"\x00" * 32
    mk1, ck1 = kdf_ck(ck)
    mk1b, ck1b = kdf_ck(ck)
    assert (mk1, ck1) == (mk1b, ck1b)
    assert mk1 != ck1
    # A deterministic chain always yields the same sequence.
    _, ck2 = kdf_ck(ck1)
    _, ck2b = kdf_ck(ck1b)
    assert ck2 == ck2b


def test_kdf_rk_self_consistency() -> None:
    rk = b"r" * 32
    dh = b"d" * 32
    a = kdf_rk(rk, dh)
    b = kdf_rk(rk, dh)
    assert a == b
    # Different inputs give different outputs.
    assert kdf_rk(rk, b"D" * 32) != a
    assert kdf_rk(b"R" * 32, dh) != a


def test_alternating_hundred_messages() -> None:
    alice, bob, ad = _establish_session()
    for i in range(100):
        sender, recv = (alice, bob) if i % 2 == 0 else (bob, alice)
        msg = f"msg-{i}".encode()
        h, ct, _mk = ratchet_encrypt(sender, msg, ad)
        out = ratchet_decrypt(recv, h, ct, ad)
        assert out == msg


def test_out_of_order_up_to_100() -> None:
    alice, bob, ad = _establish_session()
    # Alice sends 100 messages without Bob replying.
    envelopes = []
    for i in range(100):
        h, ct, _mk = ratchet_encrypt(alice, f"a-{i}".encode(), ad)
        envelopes.append((i, h, ct))

    rng = random.Random(1234)
    rng.shuffle(envelopes)
    for i, h, ct in envelopes:
        out = ratchet_decrypt(bob, h, ct, ad)
        assert out == f"a-{i}".encode()


def test_max_skip_enforced() -> None:
    alice, bob, ad = _establish_session()
    # Send one message so Bob's receiving chain is initialised.
    h, ct, _mk = ratchet_encrypt(alice, b"prime", ad)
    ratchet_decrypt(bob, h, ct, ad)
    # Now skip far ahead: send DEFAULT_MAX_SKIP + 2 messages, Bob sees only the last.
    for _ in range(DEFAULT_MAX_SKIP + 2):
        ratchet_encrypt(alice, b"skip", ad)
    h, ct, _mk = ratchet_encrypt(alice, b"final", ad)
    with pytest.raises(SignalCryptoError):
        ratchet_decrypt(bob, h, ct, ad)


def test_tampered_ciphertext_rejected() -> None:
    alice, bob, ad = _establish_session()
    h, ct, _mk = ratchet_encrypt(alice, b"secret", ad)
    tampered = bytearray(ct)
    tampered[-1] ^= 1
    with pytest.raises(SignalCryptoError):
        ratchet_decrypt(bob, h, bytes(tampered), ad)


def test_wrong_ad_rejected() -> None:
    alice, bob, ad = _establish_session()
    h, ct, mk = ratchet_encrypt(alice, b"secret", ad)
    msg = SignalMessage(header=h, ciphertext=ct)
    wire = msg.encode(ad[:32], ad[32:], mk)
    decoded = SignalMessage.decode(wire)
    with pytest.raises(SignalCryptoError):
        ratchet_decrypt(
            bob,
            decoded.header,
            decoded.ciphertext,
            b"wrong ad" + ad,
            verify_mac=lambda mac_key: decoded.verify_mac(b"wrong" + ad[:27], ad[32:], mac_key),
        )


def test_verify_mac_fails_closed_on_undecoded_message() -> None:
    """verify_mac must not silently pass a message that carries no MAC.

    A SignalMessage built in code (not via ``decode``) has no ``_mac`` to
    check against; verifying it must raise rather than return as if the
    MAC were valid.
    """
    alice, _bob, ad = _establish_session()
    h, ct, mk = ratchet_encrypt(alice, b"secret", ad)
    msg = SignalMessage(header=h, ciphertext=ct)  # no _body / _mac
    with pytest.raises(SignalCryptoError):
        msg.verify_mac(ad[:32], ad[32:], mk)


def test_wire_format_signal_message() -> None:
    alice, bob, ad = _establish_session()
    h, ct, mk = ratchet_encrypt(alice, b"hello", ad)
    msg = SignalMessage(header=h, ciphertext=ct)
    wire = msg.encode(ad[:32], ad[32:], mk)
    round_trip = SignalMessage.decode(wire)
    assert wire[0] == 0x33
    assert len(wire[-8:]) == 8
    body = WhisperMessage()
    body.ParseFromString(wire[1:-8])
    assert body.ratchetKey == b"\x05" + h.dh
    assert round_trip.header.dh == h.dh
    assert round_trip.header.pn == h.pn
    assert round_trip.header.n == h.n
    assert round_trip.ciphertext == ct


def test_wire_format_prekey_signal_message() -> None:
    inner = SignalMessage(
        header=_dummy_header(),
        ciphertext=b"X" * 48,
    )
    pksm = PreKeySignalMessage(
        registration_id=0,
        one_time_pre_key_id=42,
        signed_pre_key_id=1,
        base_key=b"B" * 32,
        identity_key=b"I" * 32,
        message=inner,
    )
    sender = b"S" * 32
    receiver = b"R" * 32
    wire = pksm.encode(sender, receiver, b"M" * 32)
    round_trip = PreKeySignalMessage.decode(wire)
    assert wire[0] == 0x33
    body = PreKeyWhisperMessage()
    body.ParseFromString(wire[1:])
    assert body.baseKey == b"\x05" + b"B" * 32
    assert body.identityKey == b"\x05" + b"I" * 32
    assert round_trip.registration_id == 0
    assert round_trip.one_time_pre_key_id == 42
    assert round_trip.signed_pre_key_id == 1
    assert round_trip.base_key == b"B" * 32
    assert round_trip.identity_key == b"I" * 32
    assert round_trip.message.ciphertext == b"X" * 48


def _dummy_header() -> MessageHeader:
    return MessageHeader(dh=b"D" * 32, pn=0, n=0)
