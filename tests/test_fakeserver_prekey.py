# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Item 4: the client uploads one-time prekeys and can consume them.

End-to-end over the fake server: on login the client publishes an OPK
batch via ``<iq xmlns="encrypt" type="set">``, and an inbound pkmsg that
references one of those uploaded keys decrypts (proving the private half
was persisted and the ``get_one_time_pre_key`` gap is closed).
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client
from pywhats.binary.node import Node
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


def _first_opk(upload: Node) -> tuple[int, bytes]:
    lst = upload.get_child("list")
    assert lst is not None
    key = lst.get_children("key")[0]
    id_child = key.get_child("id")
    val_child = key.get_child("value")
    assert id_child is not None and val_child is not None
    return int.from_bytes(id_child.content_bytes(), "big"), val_child.content_bytes()


async def test_client_uploads_prekeys_on_login() -> None:
    device = paired_device()
    async with FakeWhatsAppServer() as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)
        await poll_until(lambda: bool(server.prekey_uploads))

        upload = server.prekey_uploads[0]
        assert upload.get_str("type") == "set"
        assert upload.get_str("xmlns") == "encrypt"
        lst = upload.get_child("list")
        assert lst is not None and len(lst.get_children("key")) > 0
        await client.disconnect()


async def test_no_reupload_when_server_has_enough_prekeys() -> None:
    """Reconnect with a healthy OPK pool: count is queried, nothing uploaded.

    whatsmeow handleConnectSuccess only calls uploadPreKeys when the
    server count drops below MinPreKeyCount.
    """
    device = paired_device()
    async with FakeWhatsAppServer(initial_prekey_count=50) as server:
        client = Client(ws_url=server.url)
        client._device = device

        await _connect(client, server)
        await poll_until(lambda: bool(server.prekey_count_queries))
        # The activator sends <ib unified_session> right after the prekey
        # step, so once that arrives the refill decision has been made.
        await poll_until(lambda: any(n.tag == "ib" for n in server.received))

        assert server.prekey_uploads == []
        await client.disconnect()


async def test_inbound_pkmsg_consumes_uploaded_opk() -> None:
    device = paired_device()
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))
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
        await poll_until(lambda: bool(server.prekey_uploads))

        # The peer starts a session using one of the client's *uploaded* OPKs.
        opk_id, opk_pub = _first_opk(server.prekey_uploads[0])
        await server.deliver_text(
            peer, "hi via opk", client_device=device, opk_id=opk_id, opk_public=opk_pub
        )
        await poll_until(lambda: bool(got) or bool(errors))

        assert not errors, f"pkmsg referencing an uploaded OPK failed: {errors}"
        assert got[0].text == "hi via opk"
        await client.disconnect()
