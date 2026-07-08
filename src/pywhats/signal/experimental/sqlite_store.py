# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""SQLite-backed persistence for Signal session state.

:class:`SqliteStore` keeps sessions, peer identities, the PN<->LID map,
our one-time prekeys, and the app-state sync keys (issue #35a) in a
single transactional database file, so a process restart resumes
existing Signal sessions instead of re-running
X3DH (or, worse, forcing the peer to re-pair). It implements the
:class:`~pywhats.signal.experimental.store.SessionStore`,
:class:`~pywhats.signal.experimental.identity_store.IdentityStore`, and
:class:`~pywhats.signal.experimental.lid_map.LidMap` protocols, so it is a
drop-in backend — no call sites change.

Each write is its own committed transaction (autocommit), matching the
durability the file stores offered while keeping everything in one file
that is created with mode ``0600``. Writes that must land together —
e.g. the receiver's ratchet-session + peer-identity pair — can be
grouped with :meth:`SqliteStore.transaction`.

WARNING: This database holds ratchet keys and peer identities in the
clear. Disk encryption is the caller's responsibility. See ``SECURITY.md``.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path

from pywhats.appstate.keys import AppStateSyncKey
from pywhats.appstate.patches import HashState
from pywhats.appstate.store import MutationMac
from pywhats.signal.experimental.keys import OneTimePreKey
from pywhats.signal.experimental.ratchet import RatchetState
from pywhats.signal.experimental.sender_key import (
    SenderKeyState,
    deserialize_sender_key_state,
    serialize_sender_key_state,
)
from pywhats.signal.experimental.store import deserialize_state, serialize_state

__all__ = [
    "SqliteStore",
    "SqliteSessionStore",
    "SqliteIdentityStore",
    "SqliteLidMap",
    "SqlitePreKeyStore",
    "SqliteAppStateKeyStore",
    "SqliteAppStateStore",
    "SqliteSenderKeyStore",
]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    state      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    session_id TEXT PRIMARY KEY,
    identity   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS lid_map (
    pn_user  TEXT PRIMARY KEY,
    lid_user TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS prekeys (
    key_id  INTEGER PRIMARY KEY,
    private BLOB NOT NULL,
    public  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS app_state_sync_keys (
    key_id      BLOB PRIMARY KEY,
    key_data    BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    timestamp   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS app_state_version (
    name    TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    hash    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS app_state_mutation_macs (
    name      TEXT NOT NULL,
    version   INTEGER NOT NULL,
    index_mac BLOB NOT NULL,
    value_mac BLOB NOT NULL,
    PRIMARY KEY (name, version, index_mac)
);
CREATE TABLE IF NOT EXISTS sender_keys (
    group_id  TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    state     TEXT NOT NULL,
    PRIMARY KEY (group_id, sender_id)
);
"""


class SqliteStore:
    """Owns one SQLite connection and exposes the three store facets.

    Use :attr:`sessions`, :attr:`identities`, and :attr:`lid_map` as the
    ``SessionStore`` / ``IdentityStore`` / ``LidMap`` implementations. Call
    :meth:`close` when done (idempotent).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        first_create = not self._path.exists()
        # check_same_thread=False so a store method invoked from a worker
        # thread (e.g. loop.run_in_executor) does not crash; all access is
        # serialised by ``self._lock`` regardless.
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        if first_create:
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        # RLock (not Lock) so facet writes made inside a transaction()
        # block can re-enter from the same thread.
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
        self.sessions = SqliteSessionStore(self._conn, self._lock)
        self.identities = SqliteIdentityStore(self._conn, self._lock)
        self.lid_map = SqliteLidMap(self._conn, self._lock)
        self.prekeys = SqlitePreKeyStore(self._conn, self._lock)
        self.app_state_keys = SqliteAppStateKeyStore(self._conn, self._lock)
        self.app_state = SqliteAppStateStore(self._conn, self._lock)
        self.sender_keys = SqliteSenderKeyStore(self._conn, self._lock)

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """Group several facet writes into one committed transaction.

        Everything written inside the ``with`` block — across any of the
        facets, since they share this connection — commits together, or
        rolls back together if the block raises. The lock is held for the
        whole block, so concurrent writers from other threads cannot
        interleave.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise


class SqliteSessionStore:
    """``SessionStore`` backed by the shared connection's ``sessions`` table."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def load(self, session_id: str) -> RatchetState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return deserialize_state(json.loads(row[0]))

    def save(self, session_id: str, state: RatchetState) -> None:
        payload = json.dumps(serialize_state(state))
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (session_id, state) VALUES (?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET state = excluded.state",
                (session_id, payload),
            )

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))


class SqliteIdentityStore:
    """``IdentityStore`` backed by the shared connection's ``identities`` table."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def load(self, session_id: str) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT identity FROM identities WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return bytes(row[0])

    def save(self, session_id: str, identity_public: bytes) -> None:
        if len(identity_public) != 32:
            raise ValueError(f"identity_public must be 32 bytes, got {len(identity_public)}")
        with self._lock:
            self._conn.execute(
                "INSERT INTO identities (session_id, identity) VALUES (?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET identity = excluded.identity",
                (session_id, bytes(identity_public)),
            )

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM identities WHERE session_id = ?", (session_id,))


class SqliteLidMap:
    """``LidMap`` backed by the shared connection's ``lid_map`` table."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def get_lid(self, pn_user: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT lid_user FROM lid_map WHERE pn_user = ?", (pn_user,)
            ).fetchone()
        return None if row is None else str(row[0])

    def get_pn(self, lid_user: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT pn_user FROM lid_map WHERE lid_user = ?", (lid_user,)
            ).fetchone()
        return None if row is None else str(row[0])

    def set(self, pn_user: str, lid_user: str) -> None:
        # Bidirectional map: clear any conflicting old mapping on either
        # side before inserting, all inside one transaction so a crash
        # can never leave a half-updated pair.
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._conn.execute(
                    "DELETE FROM lid_map WHERE pn_user = ? OR lid_user = ?",
                    (pn_user, lid_user),
                )
                self._conn.execute(
                    "INSERT INTO lid_map (pn_user, lid_user) VALUES (?, ?)",
                    (pn_user, lid_user),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise


class SqlitePreKeyStore:
    """``PreKeyStore`` backed by the shared connection's ``prekeys`` table."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def load(self, key_id: int) -> OneTimePreKey | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT private, public FROM prekeys WHERE key_id = ?", (key_id,)
            ).fetchone()
        if row is None:
            return None
        return OneTimePreKey(key_id=key_id, private=bytes(row[0]), public=bytes(row[1]))

    def save(self, opk: OneTimePreKey) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO prekeys (key_id, private, public) VALUES (?, ?, ?) "
                "ON CONFLICT(key_id) DO UPDATE SET private = excluded.private, "
                "public = excluded.public",
                (opk.key_id, opk.private, opk.public),
            )

    def delete(self, key_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM prekeys WHERE key_id = ?", (key_id,))

    def max_id(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT MAX(key_id) FROM prekeys").fetchone()
        return int(row[0]) if row and row[0] is not None else 0


class SqliteAppStateKeyStore:
    """``AppStateKeyStore`` backed by the shared ``app_state_sync_keys`` table.

    The upsert mirrors whatsmeow's ``putAppStateSyncKeyQuery``
    (store/sqlstore/store.go): an existing row is only overwritten when
    the incoming timestamp is strictly newer.
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def get(self, key_id: bytes) -> AppStateSyncKey | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT key_data, fingerprint, timestamp FROM app_state_sync_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        if row is None:
            return None
        return AppStateSyncKey(
            key_id=key_id,
            key_data=bytes(row[0]),
            fingerprint=bytes(row[1]),
            timestamp=int(row[2]),
        )

    def put(self, key: AppStateSyncKey) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO app_state_sync_keys (key_id, key_data, fingerprint, timestamp) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key_id) DO UPDATE SET key_data = excluded.key_data, "
                "fingerprint = excluded.fingerprint, timestamp = excluded.timestamp "
                "WHERE excluded.timestamp > app_state_sync_keys.timestamp",
                (key.key_id, key.key_data, key.fingerprint, key.timestamp),
            )


class SqliteSenderKeyStore:
    """Persists group sender-key sessions, keyed by (group, sender address).

    A row holds one :class:`SenderKeyState` — our own sending state (keyed
    by our address) or a peer's receiving state (keyed by theirs). Mirrors
    libsignal's ``SenderKeyStore``.
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def load(self, group_id: str, sender_id: str) -> SenderKeyState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM sender_keys WHERE group_id = ? AND sender_id = ?",
                (group_id, sender_id),
            ).fetchone()
        if row is None:
            return None
        return deserialize_sender_key_state(json.loads(row[0]))

    def save(self, group_id: str, sender_id: str, state: SenderKeyState) -> None:
        payload = json.dumps(serialize_sender_key_state(state))
        with self._lock:
            self._conn.execute(
                "INSERT INTO sender_keys (group_id, sender_id, state) VALUES (?, ?, ?) "
                "ON CONFLICT(group_id, sender_id) DO UPDATE SET state = excluded.state",
                (group_id, sender_id, payload),
            )

    def delete(self, group_id: str, sender_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM sender_keys WHERE group_id = ? AND sender_id = ?",
                (group_id, sender_id),
            )


class SqliteAppStateStore:
    """``AppStateStore`` backed by the ``app_state_version`` +
    ``app_state_mutation_macs`` tables.

    Mirrors whatsmeow ``store/sqlstore/store.go``: the version row holds
    the collection's sync cursor (a 128-byte LT-hash), and the mutation
    MAC table backs ``get_prev_value_mac`` (``GetAppStateMutationMAC``:
    the value MAC for an index at its newest version).
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def get_version(self, name: str) -> HashState:
        with self._lock:
            row = self._conn.execute(
                "SELECT version, hash FROM app_state_version WHERE name = ?", (name,)
            ).fetchone()
        if row is None:
            return HashState()
        return HashState(version=int(row[0]), hash=bytes(row[1]))

    def put_version(self, name: str, state: HashState) -> None:
        if len(state.hash) != 128:
            raise ValueError(f"app-state hash must be 128 bytes, got {len(state.hash)}")
        with self._lock:
            self._conn.execute(
                "INSERT INTO app_state_version (name, version, hash) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET version = excluded.version, "
                "hash = excluded.hash",
                (name, state.version, state.hash),
            )

    def delete_version(self, name: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM app_state_version WHERE name = ?", (name,))
            self._conn.execute("DELETE FROM app_state_mutation_macs WHERE name = ?", (name,))

    def get_mutation_mac(self, name: str, index_mac: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value_mac FROM app_state_mutation_macs "
                "WHERE name = ? AND index_mac = ? ORDER BY version DESC LIMIT 1",
                (name, index_mac),
            ).fetchone()
        return None if row is None else bytes(row[0])

    def put_mutation_macs(self, name: str, version: int, macs: list[MutationMac]) -> None:
        if not macs:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO app_state_mutation_macs (name, version, index_mac, value_mac) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name, version, index_mac) "
                "DO UPDATE SET value_mac = excluded.value_mac",
                [(name, version, m.index_mac, m.value_mac) for m in macs],
            )

    def delete_mutation_macs(self, name: str, index_macs: list[bytes]) -> None:
        if not index_macs:
            return
        with self._lock:
            self._conn.executemany(
                "DELETE FROM app_state_mutation_macs WHERE name = ? AND index_mac = ?",
                [(name, index_mac) for index_mac in index_macs],
            )
