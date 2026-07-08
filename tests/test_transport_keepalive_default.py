# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""The transport must not run a websocket-level keepalive ping by default.

WhatsApp maintains liveness with an app-level ``<iq xmlns="w:p"><ping/>``
stanza (see pywhats.messaging.activator, matching whatsmeow keepalive.go).
WebSocket-level pings confuse the WA edge — its pong leaks into the data
stream as an application frame, so the library's ping waiter never
resolves and the socket self-closes after a few missed pongs, dropping a
perfectly healthy session. The default must therefore be OFF.
"""

from __future__ import annotations

import asyncio

import pytest
from websockets.asyncio.server import Server, ServerConnection, serve

from pywhats.socket import NoiseSocket

pytestmark = pytest.mark.asyncio


async def _start(handler) -> tuple[Server, int]:  # type: ignore[no-untyped-def]
    server = await serve(handler, "127.0.0.1", 0)
    port = next(iter(server.sockets)).getsockname()[1]
    return server, port


async def _idle(ws: ServerConnection) -> None:
    try:
        await ws.wait_closed()
    except Exception:
        pass


async def test_default_connect_starts_no_ws_keepalive() -> None:
    server, port = await _start(_idle)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}")
        await sock.connect()
        assert sock._keepalive_task is None, "WS keepalive must be disabled by default"
        assert sock.is_connected
        await sock.disconnect()
    finally:
        server.close()
        await server.wait_closed()


async def test_explicit_interval_still_enables_keepalive() -> None:
    server, port = await _start(_idle)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()
        assert sock._keepalive_task is not None
        await sock.disconnect()
    finally:
        server.close()
        await server.wait_closed()


# quiet unused-import lint for the asyncio import kept for parity
_ = asyncio
