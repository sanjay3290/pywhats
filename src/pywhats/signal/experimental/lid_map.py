# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Phone-number to LID mapping cache.

``InMemoryLidMap`` is the volatile implementation; persistent callers
use :class:`~pywhats.signal.experimental.sqlite_store.SqliteLidMap`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LidMap(Protocol):
    def get_lid(self, pn_user: str) -> str | None: ...

    def get_pn(self, lid_user: str) -> str | None: ...

    def set(self, pn_user: str, lid_user: str) -> None: ...


class InMemoryLidMap:
    """Volatile bidirectional PN <-> LID map."""

    def __init__(self) -> None:
        self._pn_to_lid: dict[str, str] = {}
        self._lid_to_pn: dict[str, str] = {}

    def get_lid(self, pn_user: str) -> str | None:
        return self._pn_to_lid.get(pn_user)

    def get_pn(self, lid_user: str) -> str | None:
        return self._lid_to_pn.get(lid_user)

    def set(self, pn_user: str, lid_user: str) -> None:
        old_lid = self._pn_to_lid.get(pn_user)
        if old_lid is not None and old_lid != lid_user:
            self._lid_to_pn.pop(old_lid, None)
        old_pn = self._lid_to_pn.get(lid_user)
        if old_pn is not None and old_pn != pn_user:
            self._pn_to_lid.pop(old_pn, None)
        self._pn_to_lid[pn_user] = lid_user
        self._lid_to_pn[lid_user] = pn_user
