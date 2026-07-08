# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for WhatsApp message-layer random padding."""

from __future__ import annotations

import pytest

from pywhats.messaging.padding import pad_random_max16, unpad_random_max16


def test_round_trip_recovers_payload() -> None:
    payload = b"hello v3"
    for _ in range(50):
        padded = pad_random_max16(payload)
        assert padded != payload, "pad should always add at least one byte"
        assert 1 <= len(padded) - len(payload) <= 16
        recovered = unpad_random_max16(padded)
        assert recovered == payload


def test_pad_byte_value_equals_pad_length() -> None:
    for _ in range(50):
        padded = pad_random_max16(b"x")
        pad_len = padded[-1]
        assert 1 <= pad_len <= 16
        assert padded[-pad_len:] == bytes([pad_len]) * pad_len


def test_unpad_rejects_invalid_pad_length() -> None:
    with pytest.raises(ValueError):
        unpad_random_max16(b"")
    with pytest.raises(ValueError):
        unpad_random_max16(b"abc\x00")  # pad_len 0
    with pytest.raises(ValueError):
        unpad_random_max16(b"abc\x11")  # pad_len 17
    with pytest.raises(ValueError):
        unpad_random_max16(b"\x05")  # pad_len exceeds payload


def test_unpad_rejects_inconsistent_pad_bytes() -> None:
    # Last byte says pad_len=3 but only 2 of the trailing 3 match.
    with pytest.raises(ValueError):
        unpad_random_max16(b"hello\x01\x03\x03")


def test_unpadding_a_bare_proto_ending_in_3_silently_strips_garbage() -> None:
    # Reproduces the failure mode: a serialized Message proto whose last
    # byte is ASCII '3' (0x33) gets interpreted as pad_len=51 — invalid,
    # and the unpad raises rather than silently stripping. This is the
    # check that catches "send hello v3" silently dropped by recipient.
    bare_proto_ending_in_3 = b"\x0a\x08hello v3"  # ends with 0x33
    with pytest.raises(ValueError):
        unpad_random_max16(bare_proto_ending_in_3)
