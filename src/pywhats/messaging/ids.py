# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Random message ID generator.

The format - sixteen uppercase hexadecimal characters - is the
conventional width used by the WhatsApp multi-device protocol for
client-generated stanza ids, as described in public protocol writeups.
Sixteen hex chars = 64 bits of entropy from ``secrets.token_bytes`` so
collisions over any reasonable conversation lifetime are vanishingly
unlikely; we additionally keep a short dedupe ring so an accidental
re-draw of the same id inside the same process is caught and
retried.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque

# Width of the id in bytes; 8 bytes -> 16 hex chars.
_ID_BYTES = 8

# How long a recently-issued id stays in the dedupe ring.
_DEDUPE_TTL_SECONDS = 3600.0

# Upper bound on how many ids we keep around for dedupe. With 64 bits of
# entropy the probability of collision inside an hour of traffic is
# negligible; the deque only exists as a tripwire for a broken RNG.
_DEDUPE_MAX = 4096


_lock = threading.Lock()
_recent: deque[tuple[str, float]] = deque()
_recent_set: set[str] = set()


def _sweep_expired(now: float) -> None:
    while _recent and now - _recent[0][1] > _DEDUPE_TTL_SECONDS:
        expired_id, _ = _recent.popleft()
        _recent_set.discard(expired_id)


def new_message_id() -> str:
    """Return a fresh uppercase-hex message id, guaranteed unique in-process.

    Ids are remembered for roughly one hour so re-use within that
    window (e.g. from a broken RNG or a test fixture hammering this
    function) is detected and retried.
    """
    now = time.monotonic()
    with _lock:
        _sweep_expired(now)
        for _ in range(16):
            candidate = secrets.token_bytes(_ID_BYTES).hex().upper()
            if candidate in _recent_set:
                continue
            _recent.append((candidate, now))
            _recent_set.add(candidate)
            if len(_recent) > _DEDUPE_MAX:
                oldest_id, _ = _recent.popleft()
                _recent_set.discard(oldest_id)
            return candidate
    # Exhausted retries -> the RNG is returning duplicates. That should
    # never happen; bail loudly rather than ship an id we know collides.
    raise RuntimeError("failed to generate a unique message id after 16 attempts")


def _reset_for_tests() -> None:  # pragma: no cover - test helper
    with _lock:
        _recent.clear()
        _recent_set.clear()
