# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for the peer identity public-key store."""

from __future__ import annotations

import pytest

from pywhats.signal.experimental import InMemoryIdentityStore


def test_inmemory_round_trip() -> None:
    store = InMemoryIdentityStore()
    sid = "alice:0@s.whatsapp.net"
    pub = b"\x01" * 32
    assert store.load(sid) is None
    store.save(sid, pub)
    assert store.load(sid) == pub
    store.delete(sid)
    assert store.load(sid) is None


def test_inmemory_rejects_wrong_length() -> None:
    store = InMemoryIdentityStore()
    with pytest.raises(ValueError):
        store.save("x", b"\x00" * 31)
    with pytest.raises(ValueError):
        store.save("x", b"\x00" * 33)
