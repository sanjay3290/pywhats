# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Signal group sender-key round-trip (issue #39).

Builds a sender's session, distributes it, and decrypts on the receiver
side — validating the chain-key ratchet, the WhisperGroup message-key
derivation, and the XEdDSA skmsg signature end to end. Mirrors libsignal
GroupCipher/GroupSessionBuilder.
"""

from __future__ import annotations

import warnings

import pytest

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.signal.experimental.sender_key import (  # noqa: E402
    InvalidSenderKeySignature,
    SenderKeyError,
    build_distribution_message,
    create_sender_key_state,
    group_decrypt,
    group_encrypt,
    process_distribution_message,
)


def test_distribute_then_decrypt_round_trip() -> None:
    sender = create_sender_key_state(key_id=7)
    skdm = build_distribution_message(sender)
    receiver = process_distribution_message(skdm)

    skmsg, sender2 = group_encrypt(sender, b"hello group")
    plaintext, _ = group_decrypt(receiver, skmsg)
    assert plaintext == b"hello group"
    # Encrypting advanced the sender's chain.
    assert sender2.iteration == 1


def test_sequential_messages_ratchet_forward() -> None:
    sender = create_sender_key_state(key_id=1)
    receiver = process_distribution_message(build_distribution_message(sender))

    state = sender
    rstate = receiver
    for i in range(5):
        skmsg, state = group_encrypt(state, f"msg-{i}".encode())
        out, rstate = group_decrypt(rstate, skmsg)
        assert out == f"msg-{i}".encode()
    assert state.iteration == 5
    assert rstate.iteration == 5


def test_out_of_order_forward_skip_is_supported() -> None:
    sender = create_sender_key_state(key_id=2)
    receiver = process_distribution_message(build_distribution_message(sender))

    # Encrypt three messages; deliver only the third (iteration 2).
    _m0, s1 = group_encrypt(sender, b"zero")
    _m1, s2 = group_encrypt(s1, b"one")
    m2, _s3 = group_encrypt(s2, b"two")

    out, rstate = group_decrypt(receiver, m2)
    assert out == b"two"
    assert rstate.iteration == 3


def test_tampered_ciphertext_fails_signature() -> None:
    sender = create_sender_key_state(key_id=3)
    receiver = process_distribution_message(build_distribution_message(sender))
    skmsg, _ = group_encrypt(sender, b"secret")
    tampered = bytearray(skmsg)
    tampered[2] ^= 0xFF  # flip a byte in the serialized body
    with pytest.raises(InvalidSenderKeySignature):
        group_decrypt(receiver, bytes(tampered))


def test_wrong_signing_key_rejected() -> None:
    sender = create_sender_key_state(key_id=4)
    other = create_sender_key_state(key_id=4)
    # Receiver built from a DIFFERENT sender's distribution message.
    receiver = process_distribution_message(build_distribution_message(other))
    skmsg, _ = group_encrypt(sender, b"secret")
    with pytest.raises(InvalidSenderKeySignature):
        group_decrypt(receiver, skmsg)


def test_chain_seed_is_unclamped_random() -> None:
    """The initial chain key must be a full 256-bit random seed.

    A borrowed X25519 private scalar would be RFC 7748-clamped
    (byte[0] & 0x07 == 0 and byte[31] & 0xC0 == 0x40 for every sample),
    silently reducing the HMAC seed's entropy and giving it curve
    structure. Over many fresh states at least one seed must break that
    clamping pattern.
    """
    seeds = [create_sender_key_state(key_id=9).chain_key for _ in range(32)]
    assert all(len(s) == 32 for s in seeds)
    low_bits_ever_set = any((s[0] & 0x07) != 0 for s in seeds)
    high_bits_ever_vary = any((s[31] & 0xC0) != 0x40 for s in seeds)
    assert low_bits_ever_set or high_bits_ever_vary


def test_replayed_old_iteration_rejected() -> None:
    sender = create_sender_key_state(key_id=5)
    receiver = process_distribution_message(build_distribution_message(sender))
    m0, s1 = group_encrypt(sender, b"zero")
    m1, _s2 = group_encrypt(s1, b"one")
    # Advance the receiver past iteration 0 by decrypting message 1.
    _out, rstate = group_decrypt(receiver, m1)
    with pytest.raises(SenderKeyError):
        group_decrypt(rstate, m0)  # iteration 0 is now in the past
