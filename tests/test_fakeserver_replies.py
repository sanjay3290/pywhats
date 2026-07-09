# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Quoted replies e2e: send_text(reply_to=) builds an ExtendedTextMessage
with ContextInfo, and inbound replies expose the quote on the event.

Outbound: replying to a received message wraps the text in
ExtendedTextMessage{text, context_info{stanza_id, participant,
quoted_message}}. Inbound: a peer's reply surfaces the quoted
stanza_id/participant/text on ``Message.quoted``.
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, Message
from pywhats.proto import ContextInfo, ExtendedTextMessage
from pywhats.proto import Message as MessageProto

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _on_connected() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_outbound_reply_builds_context_info() -> None:
    device = paired_device()
    # device=1 so the reply targets a specific device: the fakeserver
    # only knows one peer's prekey bundle, so the own-device DSM fanout
    # (triggered on a base-JID chat) would fetch the wrong bundle.
    chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
    peer = SignalPeer(jid=chat)
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        # Reply to an earlier message from the peer (built directly so the
        # outbound reply is a fresh pkmsg the peer can decrypt).
        quoted = Message(
            id="3EB0ORIGINALID99",
            chat=chat,
            sender=chat,
            text="original",
            timestamp=1751970000,
        )
        await client.send_text(chat, "my reply", reply_to=quoted)

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received the reply"
        enc_node = msgs[0].get_child("participants").get_children("to")[0].get_child("enc")  # type: ignore[union-attr]
        assert enc_node.get_str("type") == "pkmsg"  # type: ignore[union-attr]
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(),  # type: ignore[union-attr]
            client_identity_public=device.identity_public,
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        etm = proto.extended_text_message
        assert etm.text == "my reply"
        ci = etm.context_info
        assert ci.stanza_id == "3EB0ORIGINALID99"
        assert ci.participant == "15559990000@s.whatsapp.net"
        assert ci.quoted_message.conversation == "original"

        await client.disconnect()


async def test_inbound_reply_exposes_quote() -> None:
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

        proto = MessageProto()
        proto.extended_text_message.CopyFrom(
            ExtendedTextMessage(
                text="the reply",
                context_info=ContextInfo(
                    stanza_id="3EB0ORIGINALID99",
                    participant=str(device.jid),
                    quoted_message=MessageProto(conversation="what I said"),
                ),
            )
        )
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(received))
        msg = received[0]
        assert msg.text == "the reply"
        assert msg.quoted is not None
        assert msg.quoted.stanza_id == "3EB0ORIGINALID99"
        assert msg.quoted.participant == str(device.jid)
        assert msg.quoted.text == "what I said"

        await client.disconnect()
