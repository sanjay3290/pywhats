# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for :mod:`pywhats.socket.transport`.

All tests use a local ``websockets.serve`` server. Tests that exercise
keepalive behaviour use a very short keepalive interval to keep runtime
bounded (each test completes in under a second).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
import websockets
from websockets.asyncio.server import Server, ServerConnection, serve

from pywhats.errors import ConnectionClosed, NotConnected
from pywhats.socket import NoiseSocket

pytestmark = pytest.mark.asyncio


# --- server helpers --------------------------------------------------

Handler = Callable[[ServerConnection], Awaitable[None]]


async def _start_server(handler: Handler) -> tuple[Server, int]:
    server = await serve(handler, "127.0.0.1", 0)
    # websockets 13+: server.sockets is an iterable of actual sockets
    port = next(iter(server.sockets)).getsockname()[1]
    return server, port


async def _echo_framed(ws: ServerConnection) -> None:
    """Read framed messages, echo the payload back with a 3-byte prefix."""
    try:
        async for msg in ws:
            if not isinstance(msg, bytes):
                continue
            if len(msg) < 3:
                continue
            declared = int.from_bytes(msg[:3], "big")
            payload = msg[3 : 3 + declared]
            await ws.send(len(payload).to_bytes(3, "big") + payload)
    except websockets.exceptions.ConnectionClosed:
        pass


# --- tests -----------------------------------------------------------


async def test_connect_send_recv_roundtrip() -> None:
    server, port = await _start_server(_echo_framed)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()
        assert sock.is_connected
        await sock.send_frame(b"hello")
        got = await asyncio.wait_for(sock.recv_frame(), timeout=2.0)
        assert got == b"hello"
        await sock.send_frame(b"\x00\x01\x02\x03")
        got = await asyncio.wait_for(sock.recv_frame(), timeout=2.0)
        assert got == b"\x00\x01\x02\x03"
        await sock.disconnect()
        assert not sock.is_connected
    finally:
        server.close()
        await server.wait_closed()


async def test_disconnect_is_idempotent() -> None:
    server, port = await _start_server(_echo_framed)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()
        await sock.disconnect()
        await sock.disconnect()  # must not raise
        assert not sock.is_connected
    finally:
        server.close()
        await server.wait_closed()


async def test_send_frame_when_not_connected() -> None:
    sock = NoiseSocket("ws://127.0.0.1:1", keepalive_interval=3600.0)
    with pytest.raises(NotConnected):
        await sock.send_frame(b"x")


async def test_unexpected_close_raises_connection_closed() -> None:
    async def drop_after_first(ws: ServerConnection) -> None:
        try:
            await ws.recv()
        except Exception:
            pass
        await ws.close(code=1011, reason="boom")

    server, port = await _start_server(drop_after_first)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()
        await sock.send_frame(b"ping")
        with pytest.raises(ConnectionClosed):
            await asyncio.wait_for(sock.recv_frame(), timeout=3.0)
        await sock.disconnect()
    finally:
        server.close()
        await server.wait_closed()


async def test_disconnect_cancels_pending_recv() -> None:
    async def idle(ws: ServerConnection) -> None:
        try:
            await ws.wait_closed()
        except Exception:
            pass

    server, port = await _start_server(idle)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()

        async def _recv() -> bytes:
            return await sock.recv_frame()

        recv_task = asyncio.create_task(_recv())
        await asyncio.sleep(0.05)
        assert not recv_task.done()
        await sock.disconnect()
        with pytest.raises(ConnectionClosed):
            await asyncio.wait_for(recv_task, timeout=2.0)
    finally:
        server.close()
        await server.wait_closed()


async def test_concurrent_sends_are_serialized() -> None:
    server, port = await _start_server(_echo_framed)
    try:
        sock = NoiseSocket(f"ws://127.0.0.1:{port}", keepalive_interval=3600.0)
        await sock.connect()
        payloads = [f"msg-{i}".encode() for i in range(20)]
        await asyncio.gather(*(sock.send_frame(p) for p in payloads))
        received: set[bytes] = set()
        for _ in payloads:
            received.add(await asyncio.wait_for(sock.recv_frame(), timeout=2.0))
        assert received == set(payloads)
        await sock.disconnect()
    finally:
        server.close()
        await server.wait_closed()


async def test_keepalive_disconnect_on_missed_pongs() -> None:
    """A server that ignores pings should trigger disconnect after N misses."""

    async def ignore_pings(ws: ServerConnection) -> None:
        # Override the auto-pong behaviour by reading raw frames via a
        # connection configured with autopong off. The websockets server
        # auto-responds to pings, so we instead simulate "missed pongs" by
        # keeping the connection open but expecting the client's short
        # timeout to fire because we hold the event loop busy? Not reliable.
        # Simpler: just wait. The client keepalive_timeout is tiny; the
        # server's auto-pong DOES reply, so this handler path is unused
        # in the real "missed pongs" path.
        try:
            await ws.wait_closed()
        except Exception:
            pass

    # To reliably test missed pongs we use a raw TCP server that completes
    # the websocket handshake but never replies to pings. Rather than
    # reimplementing that, we exploit that websockets' server auto-responds
    # to pings — so to force missed pongs we monkey-patch the client's
    # ping method to return a never-completing future.
    server, port = await _start_server(ignore_pings)
    try:
        sock = NoiseSocket(
            f"ws://127.0.0.1:{port}",
            keepalive_interval=0.05,
            keepalive_timeout=0.05,
            max_missed_pongs=3,
        )
        await sock.connect()

        # Patch the underlying ws.ping to return a future that never resolves.
        loop = asyncio.get_running_loop()

        async def never_pong() -> asyncio.Future[float]:
            return loop.create_future()  # never set

        assert sock._ws is not None
        sock._ws.ping = never_pong  # type: ignore[assignment,method-assign]

        # Within ~3 * (interval + timeout) + slack the transport should tear
        # down and the next recv_frame should raise ConnectionClosed.
        with pytest.raises(ConnectionClosed):
            await asyncio.wait_for(sock.recv_frame(), timeout=2.0)
        await sock.disconnect()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.network
async def test_real_whatsapp_endpoint_smoke() -> None:  # pragma: no cover
    """Smoke test against the real endpoint. Skipped in CI by default."""
    sock = NoiseSocket()
    await sock.connect()
    try:
        assert sock.is_connected
    finally:
        await sock.disconnect()


# Keep pyflakes happy on the unused async-iterator import helper.
_ = AsyncIterator
