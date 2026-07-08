# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Post-``<success>`` companion-session activation.

When the WhatsApp server has accepted our login Noise handshake it
sends a ``<success ...>`` stanza and then waits for the client to
transition the session into "active companion" mode. If the client
sends nothing, the server tears the WebSocket down ~30 seconds later
with close code 1011 and the linked-device entry disappears from the
user's phone.

Baileys' base socket runs the following sequence inside its
``CB:success`` handler:

    1. Stash ``t`` (server time epoch) and ``lid`` from the success
       attrs onto the local credentials.
    2. Run prekey-bundle maintenance over ``xmlns="encrypt"``. (Not
       implemented here yet — peers can still message us via the
       identity + signed prekey published during pairing, and the
       30 s teardown is unrelated to prekey count.)
    3. Send ``<iq xmlns="passive" type="set"><active/></iq>`` and
       await the result. **This is the stanza that flips the session
       out of registration mode**; without it the teardown fires.
    4. Send a ``<ib><unified_session id="..."/></ib>`` telemetry
       beacon so the server's session log has a stable id.
    5. Send ``<presence type="available" name="..."/>`` so other
       devices/contacts see us as online (skipped if no push_name).
    6. Start an app-level ``<iq xmlns="w:p"><ping/></iq>`` keepalive
       loop. The WhatsApp server uses these IQ pings — not WebSocket
       ping/pong — for liveness; the default cadence is 30 s.

This module implements steps 1, 3, 4, 5, and 6. Step 2 is left as a
follow-up (issue: prekey upload).

The activator is a small dataclass-style holder that the receiver
fires once on ``<success>``. Errors in any individual step are logged
but do not abort the chain — the most important step is the
passive/active IQ; the others are best-effort.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Protocol

from pywhats.binary import Node, encode
from pywhats.events import JID

from .ids import new_message_id
from .receiver import PendingIqMap

_log = logging.getLogger("pywhats.messaging.activator")


_SERVER = JID(user="", server="s.whatsapp.net")


class _TransportLike(Protocol):
    async def send(self, plaintext: bytes) -> None: ...


# Hook the activator pokes after parsing ``<success>`` so the rest of
# the system (DeviceStore, Client) can persist server-issued state.
StateUpdater = Callable[["SuccessState"], Awaitable[None]]


class SuccessState:
    """Server-issued state lifted out of the ``<success>`` stanza."""

    __slots__ = ("server_time_offset_ms", "lid", "raw_t")

    def __init__(self, server_time_offset_ms: int, lid: str | None, raw_t: int | None) -> None:
        self.server_time_offset_ms = server_time_offset_ms
        self.lid = lid
        self.raw_t = raw_t


def parse_success(node: Node) -> SuccessState:
    """Pull ``t`` (server epoch seconds) and ``lid`` out of ``<success>``."""
    raw_t_str = node.get_str("t")
    raw_t: int | None
    if raw_t_str:
        try:
            raw_t = int(raw_t_str)
        except ValueError:
            raw_t = None
    else:
        raw_t = None
    if raw_t is None:
        offset_ms = 0
    else:
        offset_ms = raw_t * 1000 - int(time.time() * 1000)
    lid = node.get_str("lid") or None
    return SuccessState(server_time_offset_ms=offset_ms, lid=lid, raw_t=raw_t)


class SessionActivator:
    """Runs the post-``<success>`` flow and the app-level ping loop."""

    def __init__(
        self,
        *,
        transport: _TransportLike,
        iq_map: PendingIqMap,
        push_name: str | None = None,
        on_state: StateUpdater | None = None,
        keepalive_interval: float | None = None,
        passive_iq_timeout: float = 15.0,
        max_ping_failures: int = 3,
        on_fatal: Callable[[str], None] | None = None,
        upload_prekeys: Callable[[], Awaitable[int]] | None = None,
    ) -> None:
        self._transport = transport
        self._iq_map = iq_map
        self._push_name = push_name
        self._on_state = on_state
        # Fired once after the session goes active, to top up the server's
        # one-time prekey pool when it runs low (whatsmeow
        # handleConnectSuccess -> getServerPreKeyCount/uploadPreKeys).
        # Best-effort; failure does not abort activation.
        self._upload_prekeys = upload_prekeys
        self._keepalive_interval = keepalive_interval or float(
            os.environ.get("PYWHATS_KEEPALIVE_INTERVAL", "30")
        )
        self._passive_iq_timeout = passive_iq_timeout
        # After this many *consecutive* app-level ping failures the session
        # is presumed dead and ``on_fatal`` is fired so the owner can tear
        # the connection down. whatsmeow (keepalive.go) reconnects once the
        # keepalive has been failing for ~3 minutes; with the default 30 s
        # cadence, 3 consecutive misses lands in the same window.
        self._max_ping_failures = max_ping_failures
        self._on_fatal = on_fatal
        self._server_time_offset_ms = 0
        self._ping_task: asyncio.Task[None] | None = None
        self._closed = False

    @property
    def server_time_offset_ms(self) -> int:
        return self._server_time_offset_ms

    async def on_success(self, node: Node) -> None:
        """Entry point invoked by :class:`Receiver` on a ``<success>`` stanza."""
        state = parse_success(node)
        self._server_time_offset_ms = state.server_time_offset_ms
        _log.info(
            "activator: <success> t=%s lid=%s offset_ms=%d",
            state.raw_t,
            state.lid,
            state.server_time_offset_ms,
        )
        if self._on_state is not None:
            try:
                await self._on_state(state)
            except Exception:  # noqa: BLE001
                _log.exception("activator: on_state hook raised; continuing")

        await self._send_passive_active()
        await self._upload_prekeys_step()
        await self._send_unified_session()
        await self._send_presence_available()
        self.start_ping_loop()

    def start_ping_loop(self) -> None:
        if self._ping_task is not None and not self._ping_task.done():
            return
        self._ping_task = asyncio.create_task(self._app_ping_loop(), name="pywhats-app-ping")

    async def stop(self) -> None:
        self._closed = True
        task = self._ping_task
        if task is None:
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    # --- individual steps -------------------------------------------------

    async def _send_passive_active(self) -> None:
        iq_id = new_message_id()
        node = Node(
            tag="iq",
            attrs={
                "id": iq_id,
                "to": _SERVER,
                "xmlns": "passive",
                "type": "set",
            },
            content=[Node(tag="active")],
        )
        try:
            await self._send_iq(node, iq_id, deadline=self._passive_iq_timeout)
            _log.info("activator: passive/active iq accepted")
        except Exception:  # noqa: BLE001
            _log.exception("activator: passive/active iq failed; session may be torn down")

    async def _upload_prekeys_step(self) -> None:
        if self._upload_prekeys is None:
            return
        try:
            count = await self._upload_prekeys()
            if count:
                _log.info("activator: uploaded %d one-time prekeys", count)
        except Exception:  # noqa: BLE001
            _log.exception("activator: prekey upload failed; continuing")

    async def _send_unified_session(self) -> None:
        now_ms = int(time.time() * 1000) + self._server_time_offset_ms
        # Match Baileys' jitter window: id = (now + 3d) % 1w. The 3-day
        # offset and 1-week period are the values it ships.
        sid = (now_ms + 3 * 86_400_000) % (7 * 86_400_000)
        node = Node(
            tag="ib",
            content=[Node(tag="unified_session", attrs={"id": str(sid)})],
        )
        try:
            await self._transport.send(encode(node))
            _log.debug("activator: sent unified_session id=%d", sid)
        except Exception:  # noqa: BLE001
            _log.exception("activator: unified_session send failed; continuing")

    async def _send_presence_available(self) -> None:
        if not self._push_name:
            _log.debug("activator: skipping presence — no push_name stored")
            return
        node = Node(
            tag="presence",
            attrs={
                "name": self._push_name.replace("@", ""),
                "type": "available",
            },
        )
        try:
            await self._transport.send(encode(node))
            _log.info("activator: sent presence available name=%r", self._push_name)
        except Exception:  # noqa: BLE001
            _log.exception("activator: presence send failed; continuing")

    async def _app_ping_loop(self) -> None:
        interval = self._keepalive_interval
        _log.debug("activator: app-ping loop starting, interval=%.1fs", interval)
        failures = 0
        try:
            while not self._closed:
                await asyncio.sleep(interval)
                if self._closed:
                    return
                iq_id = new_message_id()
                node = Node(
                    tag="iq",
                    attrs={
                        "id": iq_id,
                        "to": _SERVER,
                        "xmlns": "w:p",
                        "type": "get",
                    },
                    content=[Node(tag="ping")],
                )
                try:
                    await self._send_iq(node, iq_id, deadline=interval)
                    if failures:
                        _log.info("activator: app ping recovered after %d failure(s)", failures)
                    failures = 0
                    _log.debug("activator: app ping ok")
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    failures += 1
                    _log.warning(
                        "activator: app ping failed (%d/%d consecutive)",
                        failures,
                        self._max_ping_failures,
                        exc_info=True,
                    )
                    if failures >= self._max_ping_failures:
                        reason = (
                            f"app-level keepalive: {failures} consecutive w:p ping "
                            "failures; peer presumed dead"
                        )
                        _log.error("activator: %s", reason)
                        if self._on_fatal is not None:
                            self._on_fatal(reason)
                        return
        except asyncio.CancelledError:
            _log.debug("activator: app-ping loop cancelled")
            raise
        finally:
            _log.debug("activator: app-ping loop stopped")

    async def _send_iq(self, node: Node, iq_id: str, *, deadline: float) -> Node:
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(node))
            async with asyncio.timeout(deadline):
                return await fut
        finally:
            self._iq_map.cancel(iq_id)
