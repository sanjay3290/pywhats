# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Reactions e2e: send_reaction targets a previously sent message and
inbound ReactionMessages surface as ``reaction`` events.

Outbound: the shipped stanza carries ``type="reaction"`` (whatsmeow
getTypeFromMessage) and the encrypted proto's MessageKey addresses the
reacted-to message. An empty emoji removes the reaction. Inbound: the
event carries the reactor, the target message id, the raw key
``from_me`` flag, and the emoji ("" = removed).
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, Message, Reaction
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


async def test_outbound_reaction_targets_previously_sent_message() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        sent = await client.send_text(chat, "react to me")
        reaction = await client.send_reaction(chat, sent.id, "\N{THUMBS UP SIGN}", from_me=True)
        assert reaction.from_me

        msgs = [n for n in server.received if n.tag == "message"]
        assert len(msgs) == 2, "expected the text send plus the reaction send"
        stanza = msgs[1]
        assert stanza.get_str("type") == "reaction"
        participants = stanza.get_child("participants")
        assert participants is not None
        (to_node,) = participants.get_children("to")
        enc_node = to_node.get_child("enc")
        assert enc_node is not None
        # The peer has not replied, so the session is still unacknowledged:
        # every outbound (incl. this reaction) carries the pkmsg preamble
        # until we decrypt an inbound message (libsignal behaviour).
        assert enc_node.get_str("type") == "pkmsg"
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(), client_identity_public=device.identity_public
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        rm = proto.reaction_message
        assert rm.key.id == sent.id
        assert rm.key.from_me is True
        assert rm.key.remote_jid == "15559990000@s.whatsapp.net"
        assert rm.text == "\N{THUMBS UP SIGN}"
        assert rm.sender_timestamp_ms > 0

        await client.disconnect()


async def test_reaction_removal_sends_present_empty_text() -> None:
    """Removing a reaction (empty emoji) must send ReactionMessage.text
    present-but-empty, not absent — whatsmeow BuildReaction always sets
    text, and a recipient distinguishes removal by a present empty string."""
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=1))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
        await client.send_reaction(chat, "3EB0REMOVE0001", "", from_me=True)

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received the reaction removal"
        enc_node = msgs[0].get_child("participants").get_children("to")[0].get_child("enc")  # type: ignore[union-attr]
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(),  # type: ignore[union-attr]
            client_identity_public=device.identity_public,
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        rm = proto.reaction_message
        assert rm.HasField("text"), "removal must send text present"
        assert rm.text == ""
        assert rm.key.id == "3EB0REMOVE0001"

        await client.disconnect()


async def test_inbound_reaction_emits_reaction_event() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        reactions: list[Reaction] = []
        messages: list[Message] = []

        @client.on("reaction")
        async def _on_reaction(r: Reaction) -> None:
            reactions.append(r)

        @client.on("message")
        async def _on_message(m: Message) -> None:
            messages.append(m)

        await _connect(client, server)

        proto = MessageProto()
        rm = proto.reaction_message
        rm.key.remote_jid = str(device.jid)
        rm.key.from_me = False
        rm.key.id = "3EB0TARGETMSGID1"
        rm.text = "\N{HEAVY BLACK HEART}"
        rm.sender_timestamp_ms = 1751970000000
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(reactions))
        r = reactions[0]
        assert r.sender.user == "15559990000"
        assert r.chat.user == "15559990000"
        assert r.message_id == "3EB0TARGETMSGID1"
        assert r.text == "\N{HEAVY BLACK HEART}"
        assert r.key_from_me is False
        assert r.timestamp == 1751970000000
        # A reaction is not a chat message — no message event.
        assert not messages

        await client.disconnect()


async def test_inbound_empty_reaction_means_removal() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        reactions: list[Reaction] = []

        @client.on("reaction")
        async def _on_reaction(r: Reaction) -> None:
            reactions.append(r)

        await _connect(client, server)

        proto = MessageProto()
        rm = proto.reaction_message
        rm.key.remote_jid = str(device.jid)
        rm.key.from_me = False
        rm.key.id = "3EB0TARGETMSGID1"
        rm.text = ""
        rm.sender_timestamp_ms = 1751970001000
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(reactions))
        assert reactions[0].message_id == "3EB0TARGETMSGID1"
        assert reactions[0].text == ""

        await client.disconnect()
