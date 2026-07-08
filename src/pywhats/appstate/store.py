# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""App-state sync cursor + mutation-MAC persistence (issue #35c).

Two facts must survive a reconnect for incremental app-state sync to
work against a moving version cursor:

* the per-collection :class:`~pywhats.appstate.patches.HashState` (its
  ``version`` and 128-byte LT-hash) — the cursor the next
  ``w:sync:app:state`` fetch resumes from;
* the index-MAC -> value-MAC map — so a later REMOVE (or a SET that
  replaces a value set in an *earlier* patch) can subtract the prior
  value out of the LT-hash. This backs the ``get_prev_value_mac``
  fallback :func:`~pywhats.appstate.patches.decode_patch` already
  accepts.

Mirrors whatsmeow ``store.AppStateStore``
(``GetAppStateVersion`` / ``PutAppStateVersion`` /
``DeleteAppStateVersion`` / ``GetAppStateMutationMAC`` /
``PutAppStateMutationMACs`` / ``DeleteAppStateMutationMACs`` in
``store/sqlstore/store.go``). The SQLite-backed implementation lives on
:class:`~pywhats.signal.experimental.sqlite_store.SqliteStore`; this
module holds the protocol and an in-memory implementation for tests and
pathless clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pywhats.appstate.patches import HashState

__all__ = ["MutationMac", "AppStateStore", "InMemoryAppStateStore"]


@dataclass(frozen=True)
class MutationMac:
    """One index-MAC -> value-MAC entry contributed by a SET mutation."""

    index_mac: bytes
    value_mac: bytes


class AppStateStore(Protocol):
    """Persistence for the app-state cursor + mutation MACs, per collection."""

    def get_version(self, name: str) -> HashState: ...

    def put_version(self, name: str, state: HashState) -> None: ...

    def delete_version(self, name: str) -> None: ...

    def get_mutation_mac(self, name: str, index_mac: bytes) -> bytes | None: ...

    def put_mutation_macs(self, name: str, version: int, macs: list[MutationMac]) -> None: ...

    def delete_mutation_macs(self, name: str, index_macs: list[bytes]) -> None: ...


class InMemoryAppStateStore:
    """Volatile :class:`AppStateStore` for tests and pathless clients."""

    def __init__(self) -> None:
        self._versions: dict[str, HashState] = {}
        # (name, index_mac) -> (version, value_mac); newest version wins on read.
        self._macs: dict[tuple[str, bytes], tuple[int, bytes]] = {}

    def get_version(self, name: str) -> HashState:
        return self._versions.get(name, HashState())

    def put_version(self, name: str, state: HashState) -> None:
        self._versions[name] = state

    def delete_version(self, name: str) -> None:
        self._versions.pop(name, None)
        for key in [k for k in self._macs if k[0] == name]:
            del self._macs[key]

    def get_mutation_mac(self, name: str, index_mac: bytes) -> bytes | None:
        entry = self._macs.get((name, index_mac))
        return None if entry is None else entry[1]

    def put_mutation_macs(self, name: str, version: int, macs: list[MutationMac]) -> None:
        for mac in macs:
            key = (name, mac.index_mac)
            existing = self._macs.get(key)
            # ORDER BY version DESC LIMIT 1: keep the highest-version value.
            if existing is None or version >= existing[0]:
                self._macs[key] = (version, mac.value_mac)

    def delete_mutation_macs(self, name: str, index_macs: list[bytes]) -> None:
        for index_mac in index_macs:
            self._macs.pop((name, index_mac), None)
