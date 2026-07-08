# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Storage for our own one-time pre-keys (OPKs).

The signed pre-key is a single long-lived key that lives in the
:class:`~pywhats.store.DeviceStore`. One-time pre-keys, by contrast, are a
consumable pool: we generate a batch, upload the public halves to the
WhatsApp server over ``xmlns="encrypt"``, and keep the private halves so
that when a peer starts a session it can reference an OPK id in its
``pkmsg`` and we can complete the matching X3DH.

Two implementations mirror the other stores:

  - ``InMemoryPreKeyStore``: volatile, for tests / ephemeral runs.
  - the SQLite-backed store in :mod:`pywhats.signal.experimental.sqlite_store`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pywhats.signal.experimental.keys import OneTimePreKey

__all__ = ["PreKeyStore", "InMemoryPreKeyStore"]


@runtime_checkable
class PreKeyStore(Protocol):
    def load(self, key_id: int) -> OneTimePreKey | None: ...

    def save(self, opk: OneTimePreKey) -> None: ...

    def delete(self, key_id: int) -> None: ...

    def max_id(self) -> int:
        """Highest allocated OPK id, or 0 if the pool is empty."""
        ...


class InMemoryPreKeyStore:
    """Volatile OPK pool."""

    def __init__(self) -> None:
        self._store: dict[int, OneTimePreKey] = {}

    def load(self, key_id: int) -> OneTimePreKey | None:
        return self._store.get(key_id)

    def save(self, opk: OneTimePreKey) -> None:
        self._store[opk.key_id] = opk

    def delete(self, key_id: int) -> None:
        self._store.pop(key_id, None)

    def max_id(self) -> int:
        return max(self._store, default=0)
