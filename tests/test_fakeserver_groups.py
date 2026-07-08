# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Issue #39 e2e: receive a group message (SKDM bootstrap + skmsg decrypt).

A group message from a new sender carries the 1:1-encrypted
SenderKeyDistributionMessage (pkmsg) plus the group content (skmsg). The
client processes the SKDM to establish the sender-key session, then
decrypts the skmsg and emits a group Message. Mirrors whatsmeow's group
receive path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pywhats import Client
from pywhats.binary import Node
from pywhats.events import JID, Message
from pywhats.messaging.padding import pad_random_max16, unpad_random_max16
from pywhats.proto import Message as MessageProto
from pywhats.signal.experimental import PreKeyBundle
from pywhats.signal.experimental.sender_key import (
    build_distribution_message,
    create_sender_key_state,
    group_decrypt,
    group_encrypt,
    process_distribution_message,
)
from pywhats.store import save_device_store

from .fakeserver import FakeWhatsAppServer, SignalPeer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_GROUP = JID(user="120363000000000000", server="g.us")


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _c() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_group_message_skdm_then_skmsg_decrypts(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    device = paired_device()
    save_device_store(device, session_path)
    sender = SignalPeer(jid=JID(user="17045551234", server="s.whatsapp.net", device=0))

    # The sender's group sending session.
    sk_state = create_sender_key_state(key_id=1)

    async with FakeWhatsAppServer(peer=sender) as server:
        client = Client(session_path=session_path, ws_url=server.url)
        received: list[Message] = []

        @client.on("message")
        async def _on_msg(m: Message) -> None:
            received.append(m)

        await _connect(client, server)

        # Build the SKDM as a 1:1 pkmsg (bootstraps the sender key).
        skdm_proto = MessageProto()
        skdm_proto.sender_key_distribution_message.group_id = str(_GROUP)
        skdm_proto.sender_key_distribution_message.axolotl_sender_key_distribution_message = (
            build_distribution_message(sk_state)
        )
        client_bundle = PreKeyBundle(
            identity_key=device.identity_public,
            signed_pre_key_id=device.signed_pre_key_id,
            signed_pre_key_public=device.signed_pre_key_public,
            signed_pre_key_signature=device.signed_pre_key_signature,
        )
        pkmsg = sender.encrypt_proto_to(
            client_identity_public=device.identity_public,
            client_bundle=client_bundle,
            proto=skdm_proto,
        )

        # Build the group content as an skmsg.
        content = pad_random_max16(MessageProto(conversation="hello group!").SerializeToString())
        skmsg, _new = group_encrypt(sk_state, content)

        node = Node(
            tag="message",
            attrs={
                "id": "group-1",
                "from": _GROUP,
                "participant": sender.jid,
                "type": "text",
                "t": "1783000000",
            },
            content=[
                Node(tag="enc", attrs={"v": "2", "type": "pkmsg"}, content=pkmsg),
                Node(tag="enc", attrs={"v": "2", "type": "skmsg"}, content=skmsg),
            ],
        )
        await server.deliver(node)

        await poll_until(lambda: bool(received), timeout_s=5.0)
        await client.disconnect()

    assert len(received) == 1
    msg = received[0]
    assert msg.text == "hello group!"
    assert msg.chat.user == "120363000000000000"
    assert msg.sender.user == "17045551234"


async def test_send_group_text_fans_out_skdm_and_skmsg(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    device = paired_device()
    save_device_store(device, session_path)
    peer = SignalPeer(jid=JID(user="17045559999", server="s.whatsapp.net", device=0))

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(session_path=session_path, ws_url=server.url)
        await _connect(client, server)
        sent = await client.send_group_text(_GROUP, "sent to the group", [peer.jid])
        await client.disconnect()

    assert sent.text == "sent to the group"

    # The server received a group message: <message to=group>
    #   <participants><to jid=peer><enc pkmsg></to></participants>
    #   <enc type=skmsg>.
    group_msg = next(
        n
        for n in server.received
        if n.tag == "message"
        and isinstance(n.attrs.get("to"), JID)
        and n.attrs["to"].server == "g.us"
    )
    participants = group_msg.get_child("participants")
    assert participants is not None
    to_node = participants.get_children("to")[0]
    skdm_enc = to_node.get_child("enc")
    assert skdm_enc is not None and skdm_enc.get_str("type") in ("pkmsg", "msg")
    skmsg_enc = next(e for e in group_msg.get_children("enc") if e.get_str("type") == "skmsg")

    # A participant can bootstrap the sender key from the SKDM and decrypt.
    skdm_plain = peer.decrypt_pkmsg(
        skdm_enc.content_bytes(), client_identity_public=device.identity_public
    )
    skdm_proto = MessageProto()
    skdm_proto.ParseFromString(skdm_plain)
    axolotl = skdm_proto.sender_key_distribution_message.axolotl_sender_key_distribution_message
    peer_state = process_distribution_message(axolotl)

    plaintext, _ = group_decrypt(peer_state, skmsg_enc.content_bytes())
    content = MessageProto()
    content.ParseFromString(unpad_random_max16(plaintext))
    assert content.conversation == "sent to the group"
