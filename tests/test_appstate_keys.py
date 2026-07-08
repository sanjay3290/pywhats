# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the app-state sync-key store (issue #35a).

Mirrors whatsmeow's ``PutAppStateSyncKey`` semantics
(``store/sqlstore/store.go`` ``putAppStateSyncKeyQuery``): keys are
upserted by ``key_id``, and an existing row is only overwritten when the
incoming timestamp is strictly newer — a re-delivered old key share must
never clobber a fresher key.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pywhats.appstate import AppStateKeyStore, AppStateSyncKey, InMemoryAppStateKeyStore
from pywhats.signal.experimental.sqlite_store import SqliteStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[AppStateKeyStore]:
    if request.param == "memory":
        yield InMemoryAppStateKeyStore()
    else:
        backend = SqliteStore(tmp_path / "state.db")
        yield backend.app_state_keys
        backend.close()


def _key(
    *,
    key_id: bytes = b"\x00\x00\x01",
    key_data: bytes = b"K" * 32,
    fingerprint: bytes = b"fp-bytes",
    timestamp: int = 1_751_000_000,
) -> AppStateSyncKey:
    return AppStateSyncKey(
        key_id=key_id, key_data=key_data, fingerprint=fingerprint, timestamp=timestamp
    )


def test_get_unknown_key_returns_none(store: AppStateKeyStore) -> None:
    assert store.get(b"\xff\xff\xff") is None


def test_put_then_get_roundtrips_all_fields(store: AppStateKeyStore) -> None:
    key = _key()
    store.put(key)
    assert store.get(key.key_id) == key


def test_put_with_newer_timestamp_overwrites(store: AppStateKeyStore) -> None:
    store.put(_key(key_data=b"A" * 32, timestamp=100))
    store.put(_key(key_data=b"B" * 32, fingerprint=b"fp-new", timestamp=200))
    got = store.get(b"\x00\x00\x01")
    assert got is not None
    assert got.key_data == b"B" * 32
    assert got.fingerprint == b"fp-new"
    assert got.timestamp == 200


def test_put_with_older_timestamp_does_not_overwrite(store: AppStateKeyStore) -> None:
    store.put(_key(key_data=b"B" * 32, timestamp=200))
    store.put(_key(key_data=b"A" * 32, timestamp=100))
    got = store.get(b"\x00\x00\x01")
    assert got is not None
    assert got.key_data == b"B" * 32
    assert got.timestamp == 200


def test_put_with_equal_timestamp_does_not_overwrite(store: AppStateKeyStore) -> None:
    # whatsmeow's upsert requires excluded.timestamp to be *strictly*
    # greater than the stored one.
    store.put(_key(key_data=b"B" * 32, timestamp=200))
    store.put(_key(key_data=b"A" * 32, timestamp=200))
    got = store.get(b"\x00\x00\x01")
    assert got is not None
    assert got.key_data == b"B" * 32


def test_keys_are_independent_by_key_id(store: AppStateKeyStore) -> None:
    store.put(_key(key_id=b"\x00\x00\x01", key_data=b"A" * 32))
    store.put(_key(key_id=b"\x00\x00\x02", key_data=b"B" * 32))
    got1 = store.get(b"\x00\x00\x01")
    got2 = store.get(b"\x00\x00\x02")
    assert got1 is not None and got1.key_data == b"A" * 32
    assert got2 is not None and got2.key_data == b"B" * 32


def test_sqlite_keys_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    key = _key()
    backend = SqliteStore(path)
    backend.app_state_keys.put(key)
    backend.close()

    reopened = SqliteStore(path)
    try:
        assert reopened.app_state_keys.get(key.key_id) == key
    finally:
        reopened.close()
