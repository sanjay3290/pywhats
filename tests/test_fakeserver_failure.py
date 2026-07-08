# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Server <failure> handling (login rejection / logged out).

Discovered live: on a resume where the linked device has been removed, the
WA edge sends ``<failure reason="401" location="rva"/>`` and closes. The
receiver previously ignored the stanza, so the disconnect looked silent.
It must now surface a ``logged_out`` event and log the reason.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from pywhats import Client

from .fakeserver import FakeWhatsAppServer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio


async def test_failure_401_emits_logged_out(caplog: pytest.LogCaptureFixture) -> None:
    device = paired_device()
    # send_success=False mimics a login the server rejects outright.
    async with FakeWhatsAppServer(send_success=False) as server:
        client = Client(ws_url=server.url)
        client._device = device

        logged_out: list[str] = []

        @client.on("logged_out")
        async def _on_logged_out(reason: str) -> None:
            logged_out.append(reason)

        connected = asyncio.Event()

        @client.on("connected")
        async def _on_connected() -> None:
            connected.set()

        await client.connect()
        await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
        await asyncio.wait_for(connected.wait(), timeout=5.0)

        with caplog.at_level(logging.ERROR, logger="pywhats.messaging.receiver"):
            await server.deliver_failure(reason="401", location="rva")
            await poll_until(lambda: bool(logged_out))

        assert logged_out == ["401"]
        assert any("failure" in r.message.lower() and "401" in r.message for r in caplog.records), (
            "expected a logged failure reason"
        )

        await client.disconnect()
