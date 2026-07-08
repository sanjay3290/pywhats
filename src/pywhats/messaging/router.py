# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Outbound stanza -> future correlation map.

The sender fires a ``<message id=...>`` stanza down the Noise transport
and then suspends on an :class:`asyncio.Future` keyed by that id. The
server's response - an ``<ack>`` for the happy path, a ``<retry>`` when
our Signal session was wrong - is dispatched here by whichever
component owns the frame reader. That component lives in issue #10; for
now the sender only depends on the small :class:`AckRouterProtocol`
surface so tests can plug in a mock.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RetrySignal:
    """Server asked us to retry. Carries whatever attributes the server sent.

    The sender only uses this as a flag today; the attributes are
    threaded through so higher layers can inspect the retry count or
    error code when the full retry protocol lands.
    """

    attrs: dict[str, str]


class AckRouterProtocol(Protocol):
    """Narrow surface the sender needs. Kept small so tests can mock it."""

    def register(self, message_id: str) -> asyncio.Future[RetrySignal | None]: ...

    def cancel(self, message_id: str) -> None: ...


class AckRouter:
    """Default in-memory implementation of :class:`AckRouterProtocol`.

    TODO(#10): wire the real frame reader so ``resolve_ack`` /
    ``resolve_retry`` are called when a matching stanza arrives.
    """

    def __init__(self) -> None:
        self._pending: dict[str, asyncio.Future[RetrySignal | None]] = {}
        self._lock = asyncio.Lock()

    def register(self, message_id: str) -> asyncio.Future[RetrySignal | None]:
        if message_id in self._pending:
            raise ValueError(f"message id already pending: {message_id!r}")
        fut: asyncio.Future[RetrySignal | None] = asyncio.get_event_loop().create_future()
        self._pending[message_id] = fut
        return fut

    def cancel(self, message_id: str) -> None:
        fut = self._pending.pop(message_id, None)
        if fut is not None and not fut.done():
            fut.cancel()

    def resolve_ack(self, message_id: str) -> None:
        """Called by the reader task when an ``<ack>`` stanza arrives."""
        fut = self._pending.pop(message_id, None)
        if fut is not None and not fut.done():
            fut.set_result(None)

    def resolve_retry(self, message_id: str, attrs: dict[str, str]) -> None:
        """Called by the reader task when a ``<retry>`` stanza arrives."""
        fut = self._pending.pop(message_id, None)
        if fut is not None and not fut.done():
            fut.set_result(RetrySignal(attrs=attrs))

    def pending_ids(self) -> list[str]:
        return list(self._pending.keys())
