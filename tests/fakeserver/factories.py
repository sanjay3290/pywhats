# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Shared factories for fake-server integration tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from pywhats.events import JID
from pywhats.pairing import make_fresh_device
from pywhats.store import DeviceStore, JIDTuple


def paired_device(*, user: str = "15551230000", device_id: int = 3) -> DeviceStore:
    """Return a DeviceStore that looks like it has completed pairing.

    Enough to drive ``Client.connect`` down the login-resume path: it has
    a JID, so ``connect()`` chooses ``_run_login`` over ``_run_pairing``.
    """
    dev = make_fresh_device()
    dev.jid = JIDTuple(user=user, server="s.whatsapp.net", device=device_id)
    dev.device_id = device_id
    dev.push_name = "Tester"
    return dev


def peer_jid(user: str = "15559990000", device: int = 0) -> JID:
    return JID(user=user, server="s.whatsapp.net", device=device)


async def poll_until(pred: Callable[[], bool], *, timeout_s: float = 5.0) -> None:
    """Await until ``pred()`` is truthy or ``timeout_s`` elapses."""

    async def _loop() -> None:
        while not pred():  # noqa: ASYNC110 — polling a caller-supplied predicate
            await asyncio.sleep(0.02)

    await asyncio.wait_for(_loop(), timeout=timeout_s)
