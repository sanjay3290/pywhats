# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Low-level websocket transport for the WhatsApp multi-device protocol.

This module provides :class:`NoiseSocket`, a framed byte-pipe that sits on top
of a websocket connection to WhatsApp's edge. It speaks the simple framing
used on the wire — a 3-byte big-endian length prefix followed by the payload —
and exposes an asynchronous ``send_frame`` / ``recv_frame`` API.

Note on the class name: despite the ``NoiseSocket`` name, this class does
**not** perform any Noise Protocol encryption. It is the raw framed socket
underneath. The Noise XX handshake is handled at a higher layer (see issue
#5) once the transport is connected.

Protocol details (endpoint, framing, keepalive cadence) are drawn from public
prose writeups of the WhatsApp Web / multi-device protocol and from the
documentation of the ``websockets`` library. Sources:

* The ``websockets`` library docs — https://websockets.readthedocs.io/
* Public writeups describing the 3-byte length prefix framing used by the
  WhatsApp Web endpoint.
"""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import Any

import websockets
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed as WSConnectionClosed

from pywhats.errors import ConnectionClosed, NotConnected

__all__ = ["NoiseSocket"]

_log = logging.getLogger("pywhats.socket")

DEFAULT_URL = "wss://web.whatsapp.com/ws/chat"
DEFAULT_ORIGIN = "https://web.whatsapp.com"
DEFAULT_QUEUE_MAXSIZE = 256
# Only consulted when WS-level keepalive is explicitly enabled (opt-in).
DEFAULT_KEEPALIVE_TIMEOUT = 30.0
DEFAULT_MAX_MISSED_PONGS = 3
# Max payload len the 3-byte prefix can describe.
_MAX_FRAME_LEN = (1 << 24) - 1


class NoiseSocket:
    """Framed websocket transport to the WhatsApp edge.

    Frames are bytes prefixed with a 3-byte big-endian length header on the
    wire. The class is safe to use from multiple tasks: ``send_frame`` uses
    a send lock, and ``recv_frame`` pulls from a bounded inbound queue that
    is filled by a single reader task.
    """

    def __init__(
        self,
        url: str = DEFAULT_URL,
        *,
        origin: str = DEFAULT_ORIGIN,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        keepalive_interval: float | None = None,
        keepalive_timeout: float | None = None,
        max_missed_pongs: int = DEFAULT_MAX_MISSED_PONGS,
    ) -> None:
        self._url = url
        self._origin = origin
        self._queue_maxsize = queue_maxsize
        # WebSocket-level keepalive is OPT-IN and OFF by default. WhatsApp
        # maintains liveness with an app-level ``<iq xmlns="w:p"><ping/>``
        # stanza (see pywhats.messaging.activator, matching whatsmeow
        # keepalive.go). WS-level pings confuse the WA edge — its pong
        # arrives as an application data frame, so the library's ping
        # waiter never resolves and the socket self-closes after a few
        # "missed" pongs, dropping a healthy session after a few minutes.
        # ``PYWHATS_KEEPALIVE_INTERVAL`` is intentionally NOT read here; it
        # tunes the app-level ping cadence only. Pass ``keepalive_interval``
        # explicitly to enable WS pings (used by the transport's own tests).
        self._keepalive_interval: float | None = keepalive_interval
        self._keepalive_timeout: float = (
            keepalive_timeout if keepalive_timeout is not None else DEFAULT_KEEPALIVE_TIMEOUT
        )
        self._max_missed_pongs = max_missed_pongs

        self._ws: ClientConnection | None = None
        self._inbound: asyncio.Queue[bytes | _Sentinel] = asyncio.Queue(maxsize=queue_maxsize)
        self._reader_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._send_lock = asyncio.Lock()
        self._closed = False
        self._close_exc: BaseException | None = None

    # ---- lifecycle -------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """True while the underlying websocket is open and no close has been observed."""
        return self._ws is not None and not self._closed

    async def connect(self, **extra_kwargs: Any) -> None:
        """Open the websocket connection and start background tasks."""
        if self._ws is not None:
            raise RuntimeError("NoiseSocket already connected")

        headers = [("Origin", self._origin)]
        _log.debug("connecting to %s", self._url)
        self._ws = await ws_connect(
            self._url,
            additional_headers=headers,
            max_size=None,
            # WA manages liveness with an app-level "ping" stanza; WS-level
            # pings confuse the server and its PONG responses leak into the
            # data stream. Disable the library's auto-ping entirely.
            ping_interval=None,
            **extra_kwargs,
        )
        self._closed = False
        self._close_exc = None
        self._reader_task = asyncio.create_task(self._reader_loop(), name="pywhats-sock-reader")
        if self._keepalive_interval is not None and self._keepalive_interval > 0:
            self._keepalive_task = asyncio.create_task(
                self._keepalive_loop(), name="pywhats-sock-keepalive"
            )
            _log.debug("ws keepalive enabled interval=%.1fs", self._keepalive_interval)
        else:
            _log.debug("ws keepalive disabled; app-level w:p ping handles liveness")
        _log.debug("connected")

    async def disconnect(self) -> None:
        """Close the websocket. Idempotent."""
        if self._closed and self._ws is None:
            return
        self._closed = True
        ws = self._ws
        self._ws = None
        _log.debug("disconnecting")
        # Tear down background tasks first so they stop looping on a dead ws.
        for task in (self._keepalive_task, self._reader_task):
            if task is not None and not task.done():
                task.cancel()
        for task in (self._keepalive_task, self._reader_task):
            if task is None:
                continue
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._keepalive_task = None
        self._reader_task = None
        if ws is not None:
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        # Wake any waiter on recv_frame.
        await self._inbound.put(_SENTINEL)

    async def __aenter__(self) -> NoiseSocket:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.disconnect()

    # ---- framing ---------------------------------------------------

    async def send_frame(self, payload: bytes) -> None:
        """Send a single framed payload."""
        if self._ws is None or self._closed:
            raise NotConnected("socket is not connected")
        n = len(payload)
        if n > _MAX_FRAME_LEN:
            raise ValueError(f"frame too large: {n} > {_MAX_FRAME_LEN}")
        header = n.to_bytes(3, "big")
        _log.debug("send_frame len=%d", n)
        async with self._send_lock:
            ws = self._ws
            if ws is None:
                raise NotConnected("socket is not connected")
            # Prepend a one-time intro prefix on the very first frame (WA needs
            # an "intro header" before the first Noise frame — see client.py).
            intro = getattr(self, "_intro_prefix", b"")
            if intro:
                self._intro_prefix = b""
                out = intro + header + payload
            else:
                out = header + payload
            try:
                await ws.send(out)
            except WSConnectionClosed as e:
                self._close_exc = e
                raise ConnectionClosed(str(e)) from e

    async def recv_frame(self) -> bytes:
        """Wait for and return the next framed payload."""
        if self._closed and self._inbound.empty() and self._close_exc is not None:
            raise ConnectionClosed(str(self._close_exc))
        item = await self._inbound.get()
        if isinstance(item, _Sentinel):
            exc = self._close_exc
            raise ConnectionClosed(str(exc) if exc else "connection closed")
        return item

    # ---- background tasks -----------------------------------------

    async def _reader_loop(self) -> None:
        assert self._ws is not None
        ws = self._ws
        try:
            async for message in ws:
                data: bytes
                if isinstance(message, bytes):
                    data = message
                else:
                    # text frames are not expected; coerce to bytes.
                    data = message.encode("utf-8")
                # WA may stack multiple length-prefixed frames into a single
                # websocket message. Parse the 3-byte BE length prefixes
                # one at a time. If the buffer doesn't self-describe (e.g.
                # a plain echo server in tests), fall through and deliver
                # it whole.
                delivered = False
                if len(data) >= 3:
                    off = 0
                    frames: list[bytes] = []
                    while off + 3 <= len(data):
                        declared = int.from_bytes(data[off : off + 3], "big")
                        if off + 3 + declared > len(data):
                            break
                        frames.append(data[off + 3 : off + 3 + declared])
                        off += 3 + declared
                    if off == len(data) and frames:
                        for fr in frames:
                            _log.debug("recv_frame len=%d", len(fr))
                            await self._inbound.put(fr)
                        delivered = True
                if not delivered:
                    # Short buffers starting with a WebSocket control-frame
                    # opcode are control payloads leaking through:
                    #   0x88 = CLOSE (kill the session)
                    #   0x89 = PING  (ignore; the WS lib will PONG)
                    #   0x8a = PONG  (ignore; this is the server answering
                    #                  our keepalive PING and is a sign of
                    #                  a HEALTHY session, not a close)
                    if 3 <= len(data) <= 6 and data[0] == 0x88:
                        _log.debug("reader: server sent ws CLOSE payload, bytes=%s", data.hex())
                        self._close_exc = ConnectionClosed(
                            f"server closed connection (ws CLOSE payload {data.hex()})"
                        )
                        break
                    if 3 <= len(data) <= 6 and data[0] in (0x89, 0x8A):
                        _log.debug(
                            "reader: ignoring ws control payload (PING/PONG) bytes=%s",
                            data.hex(),
                        )
                        continue
                    _log.debug("recv_frame len=%d (unframed)", len(data))
                    await self._inbound.put(data)
        except asyncio.CancelledError:
            raise
        except WSConnectionClosed as e:
            _log.info("reader: ws closed by peer (%s); ending read loop", e)
            self._close_exc = e
        except Exception as e:  # noqa: BLE001
            _log.warning("reader: unexpected read error (%s); ending read loop", e)
            self._close_exc = e
        else:
            # ``async for`` ended without an exception: the peer performed a
            # clean EOF / half-close. Record a reason so recv_frame surfaces
            # it instead of a bare "connection closed".
            if self._close_exc is None:
                _log.info("reader: peer closed the stream (EOF); ending read loop")
                self._close_exc = ConnectionClosed("peer closed the stream (EOF)")
        finally:
            self._closed = True
            # Unblock any pending recv_frame.
            try:
                self._inbound.put_nowait(_SENTINEL)
            except asyncio.QueueFull:
                pass

    async def _keepalive_loop(self) -> None:
        """Send websocket pings on an interval; disconnect after N missed pongs.

        Opt-in only (see the constructor note). WhatsApp liveness normally
        rides on the app-level ``w:p`` ping instead.
        """
        assert self._ws is not None
        interval = self._keepalive_interval
        assert interval is not None
        missed = 0
        try:
            while not self._closed:
                await asyncio.sleep(interval)
                ws = self._ws
                if ws is None or self._closed:
                    return
                try:
                    waiter = await ws.ping()
                    await asyncio.wait_for(waiter, timeout=self._keepalive_timeout)
                    missed = 0
                except TimeoutError:
                    missed += 1
                    _log.debug("keepalive: missed pong %d/%d", missed, self._max_missed_pongs)
                    if missed >= self._max_missed_pongs:
                        _log.debug("keepalive: too many missed pongs, closing")
                        self._close_exc = ConnectionClosed("keepalive timeout")
                        # Force-close ws to break the reader loop.
                        try:
                            await ws.close(code=1011, reason="keepalive timeout")
                        except Exception:  # noqa: BLE001
                            pass
                        return
                except WSConnectionClosed as e:
                    self._close_exc = e
                    return
        except asyncio.CancelledError:
            raise


class _Sentinel:
    """Queue sentinel used to wake a pending ``recv_frame`` on close."""


_SENTINEL = _Sentinel()


# Re-export the websockets package for convenience in tests/consumers.
_ = websockets
