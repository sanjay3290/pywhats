# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for the IbDispatcher."""

from __future__ import annotations

import pytest

from pywhats.binary import Node, decode
from pywhats.messaging import IbDispatcher


class _FakeTransport:
    def __init__(self) -> None:
        self.outbound: list[bytes] = []

    async def send(self, plaintext: bytes) -> None:
        self.outbound.append(plaintext)


@pytest.mark.asyncio
async def test_edge_routing_calls_sink() -> None:
    transport = _FakeTransport()
    captured: list[bytes] = []
    dispatcher = IbDispatcher(transport=transport, on_routing_info=captured.append)

    ib = Node(
        tag="ib",
        content=[
            Node(
                tag="edge_routing",
                content=[Node(tag="routing_info", content=b"\x08\x02\x10\x05")],
            )
        ],
    )
    await dispatcher.handle_ib(ib)

    assert captured == [b"\x08\x02\x10\x05"]
    assert transport.outbound == []


@pytest.mark.asyncio
async def test_offline_preview_replies_with_offline_batch() -> None:
    transport = _FakeTransport()
    dispatcher = IbDispatcher(transport=transport, offline_batch_count=42)

    ib = Node(
        tag="ib",
        content=[Node(tag="offline_preview", attrs={"count": "5"})],
    )
    await dispatcher.handle_ib(ib)

    assert len(transport.outbound) == 1
    reply = decode(transport.outbound[0])
    assert reply.tag == "ib"
    batch = reply.get_child("offline_batch")
    assert batch is not None
    assert batch.get_str("count") == "42"


@pytest.mark.asyncio
async def test_unknown_child_is_ignored() -> None:
    transport = _FakeTransport()
    dispatcher = IbDispatcher(transport=transport)
    await dispatcher.handle_ib(Node(tag="ib", content=[Node(tag="frobnicate")]))
    assert transport.outbound == []


@pytest.mark.asyncio
async def test_offline_marker_only_logs() -> None:
    transport = _FakeTransport()
    dispatcher = IbDispatcher(transport=transport)
    await dispatcher.handle_ib(Node(tag="ib", content=[Node(tag="offline", attrs={"count": "3"})]))
    assert transport.outbound == []
