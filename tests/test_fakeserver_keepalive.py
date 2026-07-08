# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Scenarios (d) go-silent keep-alive and (e) half-close / EOF.

These pin down the silent-disconnect fix: a genuinely dead peer must be
detected via the app-level keep-alive and torn down with a logged
reason, and an EOF must surface as a logged ``disconnected`` rather than
a silent exit.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from pywhats import Client
from pywhats.events import JID

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device

pytestmark = pytest.mark.asyncio


async def _connect(client: Client, server: FakeWhatsAppServer) -> asyncio.Event:
    connected = asyncio.Event()

    @client.on("connected")
    async def _on_connected() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)
    return connected


async def test_silent_server_triggers_keepalive_teardown(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Fast app-level ping so repeated failures escalate quickly.
    monkeypatch.setenv("PYWHATS_KEEPALIVE_INTERVAL", "0.1")
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))

    async with FakeWhatsAppServer(peer=peer, answer_pings=False) as server:
        client = Client(ws_url=server.url)
        client._device = device

        disconnected = asyncio.Event()

        @client.on("disconnected")
        async def _on_disc() -> None:
            disconnected.set()

        with caplog.at_level(logging.WARNING):
            await _connect(client, server)
            # The server never answers w:p pings; the client must notice
            # and tear the session down instead of pinging forever.
            await asyncio.wait_for(disconnected.wait(), timeout=5.0)

        assert server.ping_count >= 1
        await client.disconnect()


async def test_eof_midsession_emits_disconnected(
    caplog: pytest.LogCaptureFixture,
) -> None:
    device = paired_device()
    async with FakeWhatsAppServer() as server:
        client = Client(ws_url=server.url)
        client._device = device

        disconnected = asyncio.Event()

        @client.on("disconnected")
        async def _on_disc() -> None:
            disconnected.set()

        await _connect(client, server)

        with caplog.at_level(logging.INFO, logger="pywhats.client"):
            await server.close_connection()
            await asyncio.wait_for(disconnected.wait(), timeout=5.0)

        # The disconnect must be observable in the logs, not a silent exit.
        assert any(
            "disconnect" in r.message.lower() or "closed" in r.message.lower()
            for r in caplog.records
            if r.name == "pywhats.client"
        ), "expected a client-level disconnect log line"

        await client.disconnect()
