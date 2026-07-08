# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Issue #38 e2e: receipts + presence over the fake server.

Outbound: the public API sends the right stanza (read receipt, presence,
subscribe). Inbound: a peer receipt / presence stanza surfaces as an
event. Mirrors whatsmeow receipt.go + presence.go.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pywhats import Client
from pywhats.binary import Node
from pywhats.events import JID, ChatPresence, Presence, Receipt
from pywhats.store import save_device_store

from .fakeserver import FakeWhatsAppServer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_PEER = JID(user="15551234567", server="s.whatsapp.net")


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _c() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_mark_read_sends_read_receipt(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        await _connect(client, server)
        await client.mark_read(_PEER, ["MSG1"])
        await poll_until(
            lambda: any(
                n.tag == "receipt" and n.get_str("type") == "read" for n in server.received
            ),
            timeout_s=5.0,
        )
        await client.disconnect()

    receipt = next(n for n in server.received if n.tag == "receipt")
    assert receipt.get_str("id") == "MSG1"
    assert receipt.get_str("type") == "read"


async def test_subscribe_presence_sends_stanza(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        await _connect(client, server)
        await client.subscribe_presence(_PEER)
        await poll_until(
            lambda: any(
                n.tag == "presence" and n.get_str("type") == "subscribe" for n in server.received
            ),
            timeout_s=5.0,
        )
        await client.disconnect()


async def test_send_presence_available_carries_name(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    device = paired_device()
    save_device_store(device, session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        await _connect(client, server)
        await client.send_presence("available")
        await poll_until(
            lambda: any(
                n.tag == "presence" and n.get_str("type") == "available" for n in server.received
            ),
            timeout_s=5.0,
        )
        await client.disconnect()

    presence = next(
        n for n in server.received if n.tag == "presence" and n.get_str("type") == "available"
    )
    assert presence.get_str("name") == device.push_name


async def test_inbound_read_receipt_emits_event(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        receipts: list[Receipt] = []

        @client.on("receipt")
        async def _on_receipt(evt: Receipt) -> None:
            receipts.append(evt)

        await _connect(client, server)
        await server.deliver(
            Node(
                tag="receipt",
                attrs={"from": _PEER, "type": "read", "id": "OUT1", "t": "1700"},
            )
        )
        await poll_until(lambda: bool(receipts), timeout_s=5.0)
        await client.disconnect()

    assert receipts[0].type == "read"
    assert receipts[0].message_ids == ["OUT1"]
    assert receipts[0].from_jid.user == "15551234567"


async def test_inbound_presence_emits_event(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        updates: list[Presence] = []

        @client.on("presence")
        async def _on_presence(evt: Presence) -> None:
            updates.append(evt)

        await _connect(client, server)
        await server.deliver(
            Node(tag="presence", attrs={"from": _PEER, "type": "unavailable", "last": "1699"})
        )
        await poll_until(lambda: bool(updates), timeout_s=5.0)
        await client.disconnect()

    assert updates[0].unavailable is True
    assert updates[0].last_seen == 1699


async def test_inbound_chatstate_emits_event(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    async with FakeWhatsAppServer() as server:
        client = Client(session_path=session_path, ws_url=server.url)
        updates: list[ChatPresence] = []

        @client.on("chat_presence")
        async def _on_chat(evt: ChatPresence) -> None:
            updates.append(evt)

        await _connect(client, server)
        await server.deliver(
            Node(tag="chatstate", attrs={"from": _PEER}, content=[Node(tag="composing")])
        )
        await poll_until(lambda: bool(updates), timeout_s=5.0)
        await client.disconnect()

    assert updates[0].state == "composing"
