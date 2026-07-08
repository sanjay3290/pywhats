# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PN <-> LID mapping cache."""

from __future__ import annotations

from pywhats.signal.experimental import InMemoryLidMap


def test_inmemory_round_trip() -> None:
    store = InMemoryLidMap()
    assert store.get_lid("15551234567") is None
    assert store.get_pn("111222333444555") is None

    store.set("15551234567", "111222333444555")

    assert store.get_lid("15551234567") == "111222333444555"
    assert store.get_pn("111222333444555") == "15551234567"


def test_inmemory_reassignment_drops_stale_reverse_mapping() -> None:
    store = InMemoryLidMap()
    store.set("15551234567", "111222333444555")
    store.set("15551234567", "999999")

    assert store.get_lid("15551234567") == "999999"
    assert store.get_pn("111222333444555") is None
    assert store.get_pn("999999") == "15551234567"
