# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""LT-hash: the summation hash that guards app-state patch integrity.

An LT-hash keeps a running 128-byte digest over an unordered *set* of
items. Adding an item and later removing it returns the digest to its
prior value, and the order of operations does not matter — the property
WhatsApp relies on to verify that a stream of SET/REMOVE mutations
produced the collection state the server claims.

Mirrors whatsmeow ``appstate/lthash/lthash.go`` (``WAPatchIntegrity``):
each item is expanded with HKDF-SHA256 (info ``"WhatsApp Patch
Integrity"``, 128 bytes) and folded into the digest as pointwise
little-endian ``uint16`` addition (for adds) or subtraction (for
removes), with wraparound.
"""

from __future__ import annotations

from collections.abc import Iterable

from pywhats.appstate.crypto import hkdf_expand

__all__ = ["subtract_then_add"]

_INFO = b"WhatsApp Patch Integrity"
_SIZE = 128


def _pointwise(base: bytearray, item: bytes, *, subtract: bool) -> None:
    comp = hkdf_expand(item, _INFO, _SIZE)
    for i in range(0, _SIZE, 2):
        x = int.from_bytes(base[i : i + 2], "little")
        y = int.from_bytes(comp[i : i + 2], "little")
        r = (x - y if subtract else x + y) & 0xFFFF
        base[i : i + 2] = r.to_bytes(2, "little")


def subtract_then_add(base: bytes, *, added: Iterable[bytes], removed: Iterable[bytes]) -> bytes:
    """Return ``base`` with ``removed`` items subtracted and ``added`` added.

    ``base`` is not mutated. Subtraction happens first, matching
    whatsmeow ``SubtractThenAddInPlace`` (the order is irrelevant to the
    result but kept identical for clarity).
    """
    out = bytearray(base)
    for item in removed:
        _pointwise(out, item, subtract=True)
    for item in added:
        _pointwise(out, item, subtract=False)
    return bytes(out)
