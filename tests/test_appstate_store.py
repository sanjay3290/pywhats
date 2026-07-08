# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the app-state version + mutation-MAC store (issue #35c).

The store persists, per collection, the sync cursor (version + 128-byte
LT-hash) and the index->value MAC map that backs ``get_prev_value_mac``.
Mirrors whatsmeow ``store.AppStateStore`` (GetAppStateVersion /
PutAppStateVersion / GetAppStateMutationMAC / PutAppStateMutationMACs /
DeleteAppStateMutationMACs, store/sqlstore/store.go).
"""

from __future__ import annotations

from pywhats.appstate.patches import HashState
from pywhats.appstate.store import InMemoryAppStateStore, MutationMac

_NAME = "regular_low"
_ZERO = b"\x00" * 128


def test_unknown_collection_returns_zero_state() -> None:
    store = InMemoryAppStateStore()
    state = store.get_version(_NAME)
    assert state.version == 0
    assert state.hash == _ZERO


def test_put_then_get_version_round_trips() -> None:
    store = InMemoryAppStateStore()
    h = bytes(range(128))
    store.put_version(_NAME, HashState(version=153, hash=h))
    got = store.get_version(_NAME)
    assert got.version == 153
    assert got.hash == h


def test_delete_version_resets_to_zero() -> None:
    store = InMemoryAppStateStore()
    store.put_version(_NAME, HashState(version=5, hash=bytes(range(128))))
    store.delete_version(_NAME)
    got = store.get_version(_NAME)
    assert got.version == 0
    assert got.hash == _ZERO


def test_get_mutation_mac_unknown_index_returns_none() -> None:
    store = InMemoryAppStateStore()
    assert store.get_mutation_mac(_NAME, b"\x01" * 32) is None


def test_put_then_get_mutation_mac() -> None:
    store = InMemoryAppStateStore()
    index_mac = b"\x02" * 32
    value_mac = b"\x03" * 32
    store.put_mutation_macs(_NAME, version=10, macs=[MutationMac(index_mac, value_mac)])
    assert store.get_mutation_mac(_NAME, index_mac) == value_mac


def test_get_mutation_mac_returns_latest_version() -> None:
    # whatsmeow getAppStateMutationMACQuery: ORDER BY version DESC LIMIT 1.
    store = InMemoryAppStateStore()
    index_mac = b"\x04" * 32
    store.put_mutation_macs(_NAME, version=1, macs=[MutationMac(index_mac, b"\xaa" * 32)])
    store.put_mutation_macs(_NAME, version=2, macs=[MutationMac(index_mac, b"\xbb" * 32)])
    assert store.get_mutation_mac(_NAME, index_mac) == b"\xbb" * 32


def test_delete_mutation_macs_removes_index() -> None:
    store = InMemoryAppStateStore()
    index_mac = b"\x05" * 32
    store.put_mutation_macs(_NAME, version=1, macs=[MutationMac(index_mac, b"\xcc" * 32)])
    store.delete_mutation_macs(_NAME, [index_mac])
    assert store.get_mutation_mac(_NAME, index_mac) is None


def test_mutation_macs_are_scoped_by_collection() -> None:
    store = InMemoryAppStateStore()
    index_mac = b"\x06" * 32
    store.put_mutation_macs("regular", version=1, macs=[MutationMac(index_mac, b"\x11" * 32)])
    assert store.get_mutation_mac("regular_low", index_mac) is None
    assert store.get_mutation_mac("regular", index_mac) == b"\x11" * 32
