# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""SQLite-backed app-state version + mutation-MAC store (issue #35c).

The ``store.app_state`` facet persists the per-collection sync cursor and
the mutation-MAC map so an incremental ``w:sync:app:state`` fetch resumes
from the right version across reconnects. Mirrors whatsmeow
``store/sqlstore/store.go`` (whatsmeow_app_state_version +
whatsmeow_app_state_mutation_macs tables).
"""

from __future__ import annotations

import warnings
from pathlib import Path

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.appstate.patches import HashState  # noqa: E402
from pywhats.appstate.store import MutationMac  # noqa: E402
from pywhats.signal.experimental.sqlite_store import SqliteStore  # noqa: E402

_NAME = "regular_low"
_ZERO = b"\x00" * 128


def _store(tmp_path: Path) -> SqliteStore:
    return SqliteStore(str(tmp_path / "acct.session.signal.db"))


def test_unknown_collection_returns_zero_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        state = store.app_state.get_version(_NAME)
        assert state.version == 0
        assert state.hash == _ZERO
    finally:
        store.close()


def test_version_survives_reopen(tmp_path: Path) -> None:
    path = str(tmp_path / "acct.session.signal.db")
    h = bytes(range(128))
    store = SqliteStore(path)
    store.app_state.put_version(_NAME, HashState(version=153, hash=h))
    store.close()

    reopened = SqliteStore(path)
    try:
        got = reopened.app_state.get_version(_NAME)
        assert got.version == 153
        assert got.hash == h
    finally:
        reopened.close()


def test_put_version_rejects_wrong_hash_length(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        import pytest

        with pytest.raises(ValueError):
            store.app_state.put_version(_NAME, HashState(version=1, hash=b"\x00" * 64))
    finally:
        store.close()


def test_delete_version_clears_macs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        index_mac = b"\x02" * 32
        store.app_state.put_version(_NAME, HashState(version=1, hash=bytes(range(128))))
        store.app_state.put_mutation_macs(_NAME, 1, [MutationMac(index_mac, b"\x03" * 32)])
        store.app_state.delete_version(_NAME)
        assert store.app_state.get_version(_NAME).version == 0
        assert store.app_state.get_mutation_mac(_NAME, index_mac) is None
    finally:
        store.close()


def test_mutation_mac_latest_version_wins(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        index_mac = b"\x04" * 32
        store.app_state.put_mutation_macs(_NAME, 1, [MutationMac(index_mac, b"\xaa" * 32)])
        store.app_state.put_mutation_macs(_NAME, 2, [MutationMac(index_mac, b"\xbb" * 32)])
        assert store.app_state.get_mutation_mac(_NAME, index_mac) == b"\xbb" * 32
    finally:
        store.close()


def test_delete_mutation_macs_removes_index(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        index_mac = b"\x05" * 32
        store.app_state.put_mutation_macs(_NAME, 1, [MutationMac(index_mac, b"\xcc" * 32)])
        store.app_state.delete_mutation_macs(_NAME, [index_mac])
        assert store.app_state.get_mutation_mac(_NAME, index_mac) is None
    finally:
        store.close()


def test_mutation_macs_persist_across_reopen_and_scope_by_name(tmp_path: Path) -> None:
    path = str(tmp_path / "acct.session.signal.db")
    index_mac = b"\x06" * 32
    store = SqliteStore(path)
    store.app_state.put_mutation_macs("regular", 7, [MutationMac(index_mac, b"\x11" * 32)])
    store.close()

    reopened = SqliteStore(path)
    try:
        assert reopened.app_state.get_mutation_mac("regular", index_mac) == b"\x11" * 32
        assert reopened.app_state.get_mutation_mac("regular_low", index_mac) is None
    finally:
        reopened.close()
