# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Edits + revoke e2e: edit_message / revoke_message build the right
ProtocolMessage, and inbound edits/revokes surface as message_edit /
message_revoke events.

Outbound: edit_message ships a ProtocolMessage{type=MESSAGE_EDIT, key,
edited_message} with an ``edit="1"`` stanza attribute; revoke_message
ships {type=REVOKE, key} with ``edit="7"`` (values from public
writeups). Inbound: the receiver dispatches those two types to dedicated
events carrying the target message id (and, for edits, the new text).
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, MessageEdit, MessageRevoke
from pywhats.proto import Message as MessageProto
from pywhats.proto import ProtocolMessage

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


async def test_outbound_edit_builds_protocol_message() -> None:
    device = paired_device()
    chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
    peer = SignalPeer(jid=chat)
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        await client.edit_message(chat, "3EB0EDITTARGET01", "edited text", from_me=True)

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received the edit"
        assert msgs[0].get_str("edit") == "1"
        enc_node = msgs[0].get_child("participants").get_children("to")[0].get_child("enc")  # type: ignore[union-attr]
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(),  # type: ignore[union-attr]
            client_identity_public=device.identity_public,
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        # An edit is wrapped in Message.edited_message (FutureProofMessage);
        # the recipient recognises an edit by this outer field, not a bare
        # protocol_message (whatsmeow BuildEdit).
        assert proto.HasField("edited_message")
        pm = proto.edited_message.message.protocol_message
        assert pm.type == ProtocolMessage.MESSAGE_EDIT
        assert pm.key.id == "3EB0EDITTARGET01"
        assert pm.key.from_me is True
        assert pm.key.remote_jid == "15559990000@s.whatsapp.net"
        assert pm.edited_message.conversation == "edited text"
        assert pm.timestamp_ms > 0

        await client.disconnect()


async def test_outbound_revoke_builds_protocol_message() -> None:
    device = paired_device()
    chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
    peer = SignalPeer(jid=chat)
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        await client.revoke_message(chat, "3EB0REVOKETARGET1", from_me=True)

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received the revoke"
        assert msgs[0].get_str("edit") == "7"
        enc_node = msgs[0].get_child("participants").get_children("to")[0].get_child("enc")  # type: ignore[union-attr]
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(),  # type: ignore[union-attr]
            client_identity_public=device.identity_public,
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        pm = proto.protocol_message
        assert pm.type == ProtocolMessage.REVOKE
        assert pm.key.id == "3EB0REVOKETARGET1"
        assert pm.key.from_me is True
        assert pm.key.remote_jid == "15559990000@s.whatsapp.net"

        await client.disconnect()


async def test_admin_revoke_uses_edit_8_and_sets_participant() -> None:
    """Revoking a message you did not send (from_me=False, i.e. a group
    admin revoke) must use edit=\"8\" (AdminRevoke) and put the original
    author in key.participant — not edit=\"7\" with no participant."""
    device = paired_device()
    chat = JID(user="15559990000", server="s.whatsapp.net", device=1)
    peer = SignalPeer(jid=chat)
    author = JID(user="15551112222", server="s.whatsapp.net")
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)

        await client.revoke_message(chat, "3EB0OTHERSMSG01", from_me=False, participant=author)

        msgs = [n for n in server.received if n.tag == "message"]
        assert msgs, "server never received the revoke"
        assert msgs[0].get_str("edit") == "8"
        enc_node = msgs[0].get_child("participants").get_children("to")[0].get_child("enc")  # type: ignore[union-attr]
        plaintext = peer.decrypt_pkmsg(
            enc_node.content_bytes(),  # type: ignore[union-attr]
            client_identity_public=device.identity_public,
        )
        proto = MessageProto()
        proto.ParseFromString(plaintext)
        pm = proto.protocol_message
        assert pm.type == ProtocolMessage.REVOKE
        assert pm.key.id == "3EB0OTHERSMSG01"
        assert pm.key.from_me is False
        assert pm.key.participant == "15551112222@s.whatsapp.net"

        await client.disconnect()


async def test_inbound_edit_emits_message_edit_event() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        edits: list[MessageEdit] = []
        messages: list[object] = []

        @client.on("message_edit")
        async def _on_edit(e: MessageEdit) -> None:
            edits.append(e)

        @client.on("message")
        async def _on_msg(m: object) -> None:
            messages.append(m)

        await _connect(client, server)

        # A real peer wraps the edit in Message.edited_message.
        proto = MessageProto()
        pm = proto.edited_message.message.protocol_message
        pm.type = ProtocolMessage.MESSAGE_EDIT
        pm.key.remote_jid = str(device.jid)
        pm.key.from_me = False
        pm.key.id = "3EB0EDITTARGET01"
        pm.edited_message.conversation = "the new text"
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(edits))
        e = edits[0]
        assert e.sender.user == "15559990000"
        assert e.chat.user == "15559990000"
        assert e.message_id == "3EB0EDITTARGET01"
        assert e.text == "the new text"
        # An edit is not a fresh chat message.
        assert not messages

        await client.disconnect()


async def test_typeless_protocol_message_is_not_treated_as_revoke() -> None:
    """A protocol_message with no explicit `type` must NOT be misread as a
    revoke: REVOKE is proto3 enum default 0, so the handler has to gate on
    field presence, not `pm.type == REVOKE`."""
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        revokes: list[MessageRevoke] = []
        edits: list[MessageEdit] = []

        @client.on("message_revoke")
        async def _on_revoke(r: MessageRevoke) -> None:
            revokes.append(r)

        @client.on("message_edit")
        async def _on_edit(e: MessageEdit) -> None:
            edits.append(e)

        await _connect(client, server)

        # A protocol message with `type` unset (only ephemeral_expiration).
        proto = MessageProto()
        proto.protocol_message.ephemeral_expiration = 604800
        await server.deliver_proto(peer, proto, client_device=device)

        # Give the receiver a beat to process, then assert nothing fired.
        await asyncio.sleep(0.3)
        assert not revokes, "type-less protocol message wrongly emitted message_revoke"
        assert not edits

        await client.disconnect()


async def test_inbound_revoke_emits_message_revoke_event() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        revokes: list[MessageRevoke] = []
        messages: list[object] = []

        @client.on("message_revoke")
        async def _on_revoke(r: MessageRevoke) -> None:
            revokes.append(r)

        @client.on("message")
        async def _on_msg(m: object) -> None:
            messages.append(m)

        await _connect(client, server)

        proto = MessageProto()
        pm = proto.protocol_message
        pm.type = ProtocolMessage.REVOKE
        pm.key.remote_jid = str(device.jid)
        pm.key.from_me = False
        pm.key.id = "3EB0REVOKETARGET1"
        await server.deliver_proto(peer, proto, client_device=device)

        await poll_until(lambda: bool(revokes))
        r = revokes[0]
        assert r.sender.user == "15559990000"
        assert r.chat.user == "15559990000"
        assert r.message_id == "3EB0REVOKETARGET1"
        assert not messages

        await client.disconnect()
