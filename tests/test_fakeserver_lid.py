# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Item 3: LID-aware inbound decryption.

A peer that established a session under its phone-number (PN) address and
then switches to LID addressing must still decrypt: the stanza carries
``sender_pn``, which lets the client map PN<->LID and migrate the existing
PN session to the LID key. Mirrors whatsmeow parseMessageSource +
StoreLIDPNMapping + migrateSessionStore (message.go).
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.events import JID, Message

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


async def test_lid_addressed_message_reuses_pn_session() -> None:
    device = paired_device()
    pn = JID(user="15559990000", server="s.whatsapp.net", device=0)
    lid = JID(user="88887777", server="lid", device=0)
    peer = SignalPeer(jid=pn)  # establishes the session under the PN address

    async with FakeWhatsAppServer(peer=peer) as server:
        client = Client(ws_url=server.url)
        client._device = device

        got: list[Message] = []
        errors: list[tuple[str, str]] = []

        @client.on("message")
        async def _on_msg(m: Message) -> None:
            got.append(m)

        @client.on("decrypt_error")
        async def _on_err(msg_id: str, reason: str) -> None:
            errors.append((msg_id, reason))

        await _connect(client, server)

        # 1) pkmsg under PN -> establishes a PN-keyed Signal session.
        await server.deliver_text(peer, "hello over pn", client_device=device)
        await poll_until(lambda: bool(got))
        assert got[0].text == "hello over pn"

        # 2) msg under LID addressing, carrying sender_pn back to the PN.
        #    Without LID mapping this fails with "no session for peer <lid>".
        await server.deliver_followup_text(
            peer,
            "hello over lid",
            client_device=device,
            from_jid=lid,
            extra_attrs={"sender_pn": pn},
        )
        await poll_until(lambda: len(got) >= 2 or bool(errors))

        assert not errors, f"LID-addressed message failed to decrypt: {errors}"
        assert got[1].text == "hello over lid"
        assert got[1].sender.server == "lid"

        await client.disconnect()
