# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Item 2: a Signal session persists across a client restart (SQLite).

Proves that after establishing a session (inbound pkmsg) and then
recreating the Client from the same ``session_path`` — i.e. a process
restart — a follow-up ``msg`` from the same peer decrypts without
re-establishing the session (no re-pair).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pywhats import Client
from pywhats.events import JID, Message
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


async def test_session_resumes_after_restart(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)
    peer = SignalPeer(jid=JID(user="15559990000", server="s.whatsapp.net", device=0))

    # --- run 1: establish the session via an inbound pkmsg -----------
    async with FakeWhatsAppServer(peer=peer) as server:
        client_a = Client(session_path=session_path, ws_url=server.url)
        got_a: list[Message] = []

        @client_a.on("message")
        async def _on_a(m: Message) -> None:
            got_a.append(m)

        await _connect(client_a, server)
        await server.deliver_text(peer, "first", client_device=client_a.device)
        await poll_until(lambda: bool(got_a))
        assert got_a[0].text == "first"
        await client_a.disconnect()

    # The SQLite database must exist on disk now.
    assert (tmp_path / "acct.session.signal.db").exists()

    # --- run 2: a fresh Client (restart) resumes the same session ----
    async with FakeWhatsAppServer(peer=peer) as server:
        client_b = Client(session_path=session_path, ws_url=server.url)
        got_b: list[Message] = []
        errors_b: list[tuple[str, str]] = []

        @client_b.on("message")
        async def _on_b(m: Message) -> None:
            got_b.append(m)

        @client_b.on("decrypt_error")
        async def _on_err(msg_id: str, reason: str) -> None:
            errors_b.append((msg_id, reason))

        await _connect(client_b, server)
        # A plain `msg` (no pkmsg) — only decryptable if the session and
        # peer identity survived the restart.
        await server.deliver_followup_text(peer, "second", client_device=client_b.device)
        await poll_until(lambda: bool(got_b) or bool(errors_b))

        assert not errors_b, f"follow-up failed to decrypt after restart: {errors_b}"
        assert got_b[0].text == "second"
        await client_b.disconnect()
