# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for the post-``<success>`` SessionActivator."""

from __future__ import annotations

import asyncio

import pytest

from pywhats.binary import Node, decode
from pywhats.messaging import PendingIqMap, SessionActivator, parse_success


class _FakeTransport:
    def __init__(self) -> None:
        self.outbound: list[bytes] = []

    async def send(self, plaintext: bytes) -> None:
        self.outbound.append(plaintext)


def _decode_all(frames: list[bytes]) -> list[Node]:
    return [decode(f) for f in frames]


def test_parse_success_extracts_t_and_lid() -> None:
    node = Node(tag="success", attrs={"t": "1700000000", "lid": "12345.0:1@lid"})
    state = parse_success(node)
    assert state.raw_t == 1700000000
    assert state.lid == "12345.0:1@lid"
    # Offset is roughly t*1000 - now_ms; not asserting exact value.
    assert isinstance(state.server_time_offset_ms, int)


def test_parse_success_handles_missing_attrs() -> None:
    state = parse_success(Node(tag="success"))
    assert state.raw_t is None
    assert state.lid is None
    assert state.server_time_offset_ms == 0


@pytest.mark.asyncio
async def test_on_success_sends_passive_active_unified_session_and_starts_ping() -> None:
    transport = _FakeTransport()
    iq_map = PendingIqMap()

    activator = SessionActivator(
        transport=transport,
        iq_map=iq_map,
        push_name="Alice",
        keepalive_interval=0.05,
        passive_iq_timeout=0.5,
    )

    async def _resolve_passive_iq() -> None:
        # The activator registers an iq id, sends, and awaits a result.
        # Drain one frame, decode it, and resolve the matching future.
        for _ in range(20):
            if transport.outbound:
                break
            await asyncio.sleep(0.01)
        frame = transport.outbound[0]
        node = decode(frame)
        assert node.tag == "iq"
        assert node.get_str("xmlns") == "passive"
        assert node.get_str("type") == "set"
        assert node.get_child("active") is not None
        iq_map.resolve(node.get_str("id"), Node(tag="iq", attrs={"id": node.get_str("id")}))

    success_node = Node(tag="success", attrs={"t": "1700000000", "lid": "x@lid"})

    resolver = asyncio.create_task(_resolve_passive_iq())
    activate = asyncio.create_task(activator.on_success(success_node))
    await asyncio.gather(resolver, activate)

    # 1st frame: passive/active iq. 2nd: unified_session ib. 3rd: presence.
    nodes = _decode_all(transport.outbound[:3])
    assert nodes[0].tag == "iq" and nodes[0].get_str("xmlns") == "passive"
    assert nodes[1].tag == "ib" and nodes[1].get_child("unified_session") is not None
    assert nodes[2].tag == "presence" and nodes[2].get_str("type") == "available"
    assert nodes[2].get_str("name") == "Alice"

    # Ping loop should be running and emit at least one w:p ping.
    for _ in range(50):
        await asyncio.sleep(0.02)
        if any(decode(f).get_str("xmlns") == "w:p" for f in transport.outbound[3:]):
            break
    pings = [f for f in transport.outbound[3:] if decode(f).get_str("xmlns") == "w:p"]
    assert pings, "expected at least one w:p ping after activation"
    # Resolve the in-flight ping so stop() returns cleanly.
    for f in pings:
        n = decode(f)
        iq_map.resolve(n.get_str("id"), Node(tag="iq", attrs={"id": n.get_str("id")}))

    await activator.stop()


@pytest.mark.asyncio
async def test_on_success_skips_presence_when_no_push_name() -> None:
    transport = _FakeTransport()
    iq_map = PendingIqMap()
    activator = SessionActivator(
        transport=transport,
        iq_map=iq_map,
        push_name=None,
        keepalive_interval=10.0,
        passive_iq_timeout=0.5,
    )

    async def _resolver() -> None:
        for _ in range(20):
            if transport.outbound:
                break
            await asyncio.sleep(0.01)
        frame = transport.outbound[0]
        node = decode(frame)
        iq_map.resolve(node.get_str("id"), Node(tag="iq", attrs={"id": node.get_str("id")}))

    success = Node(tag="success", attrs={"t": "1700000000"})
    await asyncio.gather(_resolver(), activator.on_success(success))

    tags = [decode(f).tag for f in transport.outbound]
    assert "presence" not in tags
    await activator.stop()


@pytest.mark.asyncio
async def test_state_updater_receives_lid() -> None:
    transport = _FakeTransport()
    iq_map = PendingIqMap()
    captured: list[str | None] = []

    async def _on_state(state):  # type: ignore[no-untyped-def]
        captured.append(state.lid)

    activator = SessionActivator(
        transport=transport,
        iq_map=iq_map,
        push_name=None,
        on_state=_on_state,
        keepalive_interval=10.0,
        passive_iq_timeout=0.5,
    )

    async def _resolver() -> None:
        for _ in range(20):
            if transport.outbound:
                break
            await asyncio.sleep(0.01)
        frame = transport.outbound[0]
        node = decode(frame)
        iq_map.resolve(node.get_str("id"), Node(tag="iq", attrs={"id": node.get_str("id")}))

    success = Node(tag="success", attrs={"t": "1700000000", "lid": "abc@lid"})
    await asyncio.gather(_resolver(), activator.on_success(success))

    assert captured == ["abc@lid"]
    await activator.stop()
