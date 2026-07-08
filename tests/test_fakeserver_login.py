# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Scenario (a): full handshake + login resume against the fake server."""

from __future__ import annotations

import asyncio

import pytest

from pywhats import Client

from .fakeserver import FakeWhatsAppServer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio


async def test_login_resume_handshake_and_activation() -> None:
    device = paired_device()
    async with FakeWhatsAppServer() as server:
        client = Client(ws_url=server.url)
        client._device = device  # resume from stored creds

        connected = asyncio.Event()

        @client.on("connected")
        async def _on_connected() -> None:
            connected.set()

        await client.connect()
        await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
        await asyncio.wait_for(connected.wait(), timeout=5.0)

        assert server.mode == "login"
        assert server.client_payload is not None
        assert server.client_payload.passive is True

        # The activator should flip the session active via a passive/active iq.
        await poll_until(lambda: _has_passive_iq(server))

        # And the session must stay up (no silent teardown) for a beat.
        await asyncio.sleep(0.3)
        assert not server.connection_closed.is_set()

        await client.disconnect()


def _has_passive_iq(server: FakeWhatsAppServer) -> bool:
    return any(n.tag == "iq" and n.get_str("xmlns") == "passive" for n in server.received)
