# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Dispatcher for ``<ib>`` (info-broadcast) server stanzas.

WhatsApp's server uses ``<ib>`` as a catch-all for connection-scoped
notifications: routing-info updates, offline-message preview/flush
markers, and "dirty" cache invalidation hints. The expected response
varies by child element, so we don't blanket-ack — we dispatch on the
first child's tag.

Currently implemented:
  - ``edge_routing``: stash ``routing_info`` bytes on the device for use
    on the next reconnect (appended as ``ED=<base64url>`` on the WSS URL).
  - ``offline_preview``: reply with ``<ib><offline_batch count="N"/></ib>``
    to flush the offline queue.
  - ``offline``: log only (server's "we're done flushing" marker).
  - ``dirty``: log only for now; future cleanup via
    ``<iq xmlns="urn:xmpp:whatsapp:dirty" type="set"><clean .../></iq>``.

Anything else is logged at debug level.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Protocol

from pywhats.binary import Node, encode

_log = logging.getLogger("pywhats.messaging.ib")


class _TransportLike(Protocol):
    async def send(self, plaintext: bytes) -> None: ...


# Hook for persisting routing_info on the DeviceStore.
RoutingInfoSink = Callable[[bytes], None]


class IbDispatcher:
    """Routes ``<ib>`` children to the right side-effect."""

    def __init__(
        self,
        *,
        transport: _TransportLike,
        on_routing_info: RoutingInfoSink | None = None,
        offline_batch_count: int = 100,
    ) -> None:
        self._transport = transport
        self._on_routing_info = on_routing_info
        self._offline_batch_count = offline_batch_count

    async def handle_ib(self, node: Node) -> None:
        children = list(node.get_children())
        if not children:
            _log.debug("ib: empty stanza")
            return
        for child in children:
            tag = child.tag
            if tag == "edge_routing":
                self._handle_edge_routing(child)
            elif tag == "offline_preview":
                await self._handle_offline_preview(child)
            elif tag == "offline":
                _log.info("ib: offline flush done count=%s", child.get_str("count"))
            elif tag == "dirty":
                _log.info(
                    "ib: dirty type=%s ts=%s (clean not implemented yet)",
                    child.get_str("type"),
                    child.get_str("timestamp"),
                )
            else:
                _log.debug("ib: unhandled child tag=%s", tag)

    def _handle_edge_routing(self, edge: Node) -> None:
        ri = edge.get_child("routing_info")
        if ri is None:
            _log.debug("ib: edge_routing without routing_info")
            return
        data = ri.content_bytes()
        if not data:
            return
        if self._on_routing_info is not None:
            try:
                self._on_routing_info(data)
            except Exception:  # noqa: BLE001
                _log.exception("ib: routing_info sink raised; continuing")
        _log.info("ib: stored routing_info (%d bytes)", len(data))

    async def _handle_offline_preview(self, preview: Node) -> None:
        reply = Node(
            tag="ib",
            content=[
                Node(
                    tag="offline_batch",
                    attrs={"count": str(self._offline_batch_count)},
                )
            ],
        )
        try:
            await self._transport.send(encode(reply))
            _log.debug("ib: replied offline_batch count=%d", self._offline_batch_count)
        except Exception:  # noqa: BLE001
            _log.exception("ib: offline_batch reply failed")
