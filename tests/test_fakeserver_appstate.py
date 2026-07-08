# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Issue #35a e2e: an inbound APP_STATE_SYNC_KEY_SHARE lands in SQLite.

The key share arrives as a self-sent E2E message from our own primary
(observed live 2026-07-07, device #52: 43 keys at +1.31s). The receiver
must decrypt it through the normal 1:1 path and persist every key in the
``app_state_sync_keys`` table of the client's Signal SQLite database.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pywhats import Client
from pywhats.events import JID, Message
from pywhats.proto import Message as MessageProto
from pywhats.proto import ProtocolMessage
from pywhats.signal.experimental.sqlite_store import SqliteStore
from pywhats.store import save_device_store

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


def _key_share_proto(keys: list[tuple[bytes, bytes, int]]) -> MessageProto:
    proto = MessageProto()
    pm = proto.protocol_message
    pm.type = ProtocolMessage.APP_STATE_SYNC_KEY_SHARE
    for key_id, key_data, timestamp in keys:
        key = pm.app_state_sync_key_share.keys.add()
        key.key_id.key_id = key_id
        key.key_data.key_data = key_data
        key.key_data.timestamp = timestamp
        key.key_data.fingerprint.raw_id = 42
        key.key_data.fingerprint.current_index = 0
        key.key_data.fingerprint.device_indexes.append(0)
    return proto


async def test_key_share_from_own_primary_persists_to_sqlite(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    device = paired_device()
    save_device_store(device, session_path)
    # The sender is our own primary: same user as the paired device, device 0.
    own_primary = SignalPeer(jid=JID(user="15551230000", server="s.whatsapp.net", device=0))

    async with FakeWhatsAppServer(peer=own_primary) as server:
        client = Client(session_path=session_path, ws_url=server.url)
        received: list[Message] = []

        @client.on("message")
        async def _on_message(m: Message) -> None:
            received.append(m)

        await _connect(client, server)

        proto = _key_share_proto(
            [
                (b"\x00\x00\x01", b"A" * 32, 1_751_000_001),
                (b"\x00\x00\x02", b"B" * 32, 1_751_000_002),
            ]
        )
        await server.deliver_proto(own_primary, proto, client_device=client.device)

        # The key-share protocol message is still dispatched as a message
        # event (whatsmeow dispatches events.Message for protocol
        # messages too); keys are persisted before it is emitted.
        await poll_until(lambda: bool(received))
        await client.disconnect()

    store = SqliteStore(f"{session_path}.signal.db")
    try:
        got1 = store.app_state_keys.get(b"\x00\x00\x01")
        got2 = store.app_state_keys.get(b"\x00\x00\x02")
        assert got1 is not None
        assert got1.key_data == b"A" * 32
        assert got1.timestamp == 1_751_000_001
        assert got2 is not None
        assert got2.key_data == b"B" * 32
    finally:
        store.close()
