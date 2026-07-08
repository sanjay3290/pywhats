# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Scenarios (b) inbound text and (c) outbound send_text wire shape."""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, Message

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device, poll_until

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


async def test_inbound_encrypted_text_is_decrypted_and_emitted() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        received: list[Message] = []

        @client.on("message")
        async def _on_message(m: Message) -> None:
            received.append(m)

        await _connect(client, server)
        await server.deliver_text(peer, "hello from peer", client_device=device)

        await poll_until(lambda: bool(received))
        assert received[0].text == "hello from peer"
        assert received[0].sender.user == "15559990000"

        await client.disconnect()


async def test_outbound_send_text_wire_shape() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        sent = await client.send_text(chat, "hi there")
        assert sent.text == "hi there"

        # The server must have received a well-formed <message> stanza.
        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received an outbound message"
        msg = msgs[0]
        assert msg.get_str("type") == "text"
        participants = msg.get_child("participants")
        assert participants is not None
        to_nodes = participants.get_children("to")
        assert len(to_nodes) == 1
        to = to_nodes[0]
        assert isinstance(to.get_attr("jid"), JID)
        assert to.get_attr("jid").user == "15559990000"  # type: ignore[union-attr]
        enc = to.get_child("enc")
        assert enc is not None
        assert enc.get_str("v") == "2"
        assert enc.get_str("type") == "pkmsg"  # first message -> pkmsg
        assert enc.content_bytes(), "enc had no ciphertext"

        await client.disconnect()
