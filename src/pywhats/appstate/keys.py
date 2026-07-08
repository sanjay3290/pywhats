# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""App-state sync-key material storage (issue #35a).

WhatsApp encrypts app-state mutations (contacts, pushnames,
mute/pin/archive) with root keys distributed via
``APP_STATE_SYNC_KEY_SHARE`` protocol messages, self-sent from the
primary right after pairing (43 keys in the 2026-07-07 live capture).
Every key is kept: the newest encrypts outbound mutations, older ones
decrypt older snapshots/patches.

Mirrors whatsmeow's ``store.AppStateSyncKey`` with
``PutAppStateSyncKey`` / ``GetAppStateSyncKey``
(``store/sqlstore/store.go``): a put only overwrites an existing key
when its timestamp is strictly newer, so a re-delivered old key share
never clobbers a fresher key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

__all__ = ["AppStateSyncKey", "AppStateKeyStore", "InMemoryAppStateKeyStore"]


@dataclass(frozen=True)
class AppStateSyncKey:
    """One 32-byte app-state root key, as delivered in a key share.

    ``fingerprint`` holds the serialized ``AppStateSyncKeyFingerprint``
    proto — whatsmeow marshals it the same way before storing
    (``handleAppStateSyncKeyShare``).
    """

    key_id: bytes
    key_data: bytes
    fingerprint: bytes
    timestamp: int


class AppStateKeyStore(Protocol):
    """Persistence for app-state sync keys, keyed by ``key_id``."""

    def get(self, key_id: bytes) -> AppStateSyncKey | None: ...

    def put(self, key: AppStateSyncKey) -> None: ...


class InMemoryAppStateKeyStore:
    """Volatile :class:`AppStateKeyStore` for tests and pathless clients."""

    def __init__(self) -> None:
        self._keys: dict[bytes, AppStateSyncKey] = {}

    def get(self, key_id: bytes) -> AppStateSyncKey | None:
        return self._keys.get(key_id)

    def put(self, key: AppStateSyncKey) -> None:
        existing = self._keys.get(key.key_id)
        if existing is not None and key.timestamp <= existing.timestamp:
            return
        self._keys[key.key_id] = key
