# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""The live receiver must answer server-initiated <iq type="get"> requests.

Root-caused live: WhatsApp sends the companion a server-side iq (e.g.
``urn:xmpp:ping``) and unlinks it (~60s, WS CLOSE 1011) if it goes
unanswered. The pairing loop replied to these; the live receiver did not.
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.binary.node import Node
from pywhats.events import JID

from .fakeserver import FakeWhatsAppServer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_SERVER = JID(user="", server="s.whatsapp.net")


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _on_connected() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


def _server_ping_reply(server: FakeWhatsAppServer, iq_id: str) -> Node | None:
    for n in server.received:
        if n.tag == "iq" and n.get_str("id") == iq_id and n.get_str("type") == "result":
            return n
    return None


async def test_receiver_replies_to_server_ping_iq() -> None:
    device = paired_device()
    async with FakeWhatsAppServer() as server:
        client = Client(ws_url=server.url)
        client._device = device
        await _connect(client, server)

        await server.deliver(
            Node(
                tag="iq",
                attrs={
                    "id": "srv-ping-1",
                    "type": "get",
                    "xmlns": "urn:xmpp:ping",
                    "from": _SERVER,
                },
                content=[Node(tag="ping")],
            )
        )

        await poll_until(lambda: _server_ping_reply(server, "srv-ping-1") is not None)
        reply = _server_ping_reply(server, "srv-ping-1")
        assert reply is not None
        assert reply.get_str("type") == "result"
        # The reply must be addressed back to the server.
        to = reply.get_attr("to")
        assert isinstance(to, JID)

        await client.disconnect()


async def test_receiver_still_resolves_our_own_iq_results() -> None:
    # Regression: type="result"/"error" must still resolve pending iqs, not
    # be treated as a server request. A successful send_text depends on the
    # prekey-fetch iq result resolving — exercised here implicitly.
    device = paired_device()
    from .fakeserver import SignalPeer

    peer = SignalPeer(jid=JID(user="15551234567", server="s.whatsapp.net", device=1))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device
        await _connect(client, server)
        chat = JID(user="15551234567", server="s.whatsapp.net", device=1)
        sent = await client.send_text(chat, "resolves-ok")
        assert sent.text == "resolves-ok"
        await client.disconnect()
