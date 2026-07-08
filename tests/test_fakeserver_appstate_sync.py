# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Issue #35c e2e: a ``server_sync`` notification drives an incremental fetch.

The server pushes ``<notification type="server_sync"><collection name=
version=>`` (observed live 2026-07-07, device #52: regular v109->v110). The
client must react by sending a ``w:sync:app:state`` iq from its stored
version cursor, decode the returned inline ``SyncdPatch``, and persist the
advanced version + hash + mutation MACs. Mirrors whatsmeow
``handleAppStateNotification`` -> ``fetchAppState``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats import Client
from pywhats.appstate import AppStateSyncKey
from pywhats.appstate.crypto import expand_app_state_keys
from pywhats.appstate.lthash import subtract_then_add
from pywhats.appstate.patches import HashState
from pywhats.proto import (
    KeyId,
    SyncActionData,
    SyncActionValue,
    SyncdIndex,
    SyncdMutation,
    SyncdPatch,
    SyncdRecord,
    SyncdValue,
)
from pywhats.signal.experimental.sqlite_store import SqliteStore
from pywhats.store import save_device_store

from .fakeserver import FakeWhatsAppServer
from .fakeserver.factories import paired_device, poll_until

pytestmark = pytest.mark.asyncio

_NAME = "regular"
_KEY_ID = b"\x00\x00\x2a"
_KEY_DATA = bytes(range(32, 64))
_ZERO = b"\x00" * 128


def _pkcs7(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(plaintext + bytes([pad]) * pad) + enc.finalize()


def _build_patch(
    *,
    version: int,
    prev_hash: bytes,
    index: list[str] | None = None,
    action: SyncActionValue | None = None,
) -> bytes:
    keys = expand_app_state_keys(_KEY_DATA)
    if index is None:
        index = ["mute", "999@s.whatsapp.net"]
    if action is None:
        action = SyncActionValue(timestamp=1)
    index_json = json.dumps(index, separators=(",", ":")).encode()
    plaintext = SyncActionData(index=index_json, value=action, version=3).SerializeToString()
    iv = b"\x00" * 16
    content = iv + _pkcs7(keys.value_encryption, iv, plaintext)
    mac_input = bytes([0 + 1]) + _KEY_ID + content + (len(_KEY_ID) + 1).to_bytes(8, "big")
    value_mac = hmac.new(keys.value_mac, mac_input, hashlib.sha512).digest()[:32]
    index_mac = hmac.new(keys.index, index_json, hashlib.sha256).digest()
    record = SyncdRecord(
        index=SyncdIndex(blob=index_mac),
        value=SyncdValue(blob=content + value_mac),
        key_id=KeyId(id=_KEY_ID),
    )
    patch = SyncdPatch(mutations=[SyncdMutation(operation=0, record=record)])
    new_hash = subtract_then_add(prev_hash, added=[value_mac], removed=[])
    snapshot_mac = hmac.new(
        keys.snapshot_mac,
        new_hash + version.to_bytes(8, "big") + _NAME.encode(),
        hashlib.sha256,
    ).digest()
    h = hmac.new(keys.patch_mac, snapshot_mac, hashlib.sha256)
    h.update(value_mac)
    h.update(version.to_bytes(8, "big"))
    h.update(_NAME.encode())
    patch.snapshot_mac = snapshot_mac
    patch.patch_mac = h.digest()
    patch.key_id.id = _KEY_ID
    patch.version.version = version
    return patch.SerializeToString()


async def _connect(client: Client, server: FakeWhatsAppServer) -> None:
    connected = asyncio.Event()

    @client.on("connected")
    async def _c() -> None:
        connected.set()

    await client.connect()
    await asyncio.wait_for(server.handshake_complete.wait(), timeout=5.0)
    await asyncio.wait_for(connected.wait(), timeout=5.0)


async def test_server_sync_notification_triggers_incremental_fetch(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    # Seed the app-state key and a prior version cursor (v109) so the fetch
    # is incremental, then queue the v110 patch built against that cursor.
    seed = SqliteStore(f"{session_path}.signal.db")
    seed.app_state_keys.put(
        AppStateSyncKey(key_id=_KEY_ID, key_data=_KEY_DATA, fingerprint=b"fp", timestamp=1)
    )
    seed.app_state.put_version(_NAME, HashState(version=109, hash=_ZERO))
    seed.close()

    patch_bytes = _build_patch(version=110, prev_hash=_ZERO)

    async with FakeWhatsAppServer() as server:
        server.app_state_patches[_NAME] = [patch_bytes]
        client = Client(session_path=session_path, ws_url=server.url)
        await _connect(client, server)

        await server.deliver_server_sync([(_NAME, 110)])

        await poll_until(lambda: bool(server.app_state_fetches), timeout_s=5.0)
        # Let the fetch response round-trip and persist.
        await poll_until(
            lambda: _persisted_version(session_path) == 110,
            timeout_s=5.0,
        )
        await client.disconnect()

    assert _persisted_version(session_path) == 110


async def test_server_sync_emits_mute_event(tmp_path: Path) -> None:
    session_path = str(tmp_path / "acct.session")
    save_device_store(paired_device(), session_path)

    seed = SqliteStore(f"{session_path}.signal.db")
    seed.app_state_keys.put(
        AppStateSyncKey(key_id=_KEY_ID, key_data=_KEY_DATA, fingerprint=b"fp", timestamp=1)
    )
    seed.app_state.put_version(_NAME, HashState(version=109, hash=_ZERO))
    seed.close()

    action = SyncActionValue(timestamp=1234)
    action.mute_action.muted = True
    action.mute_action.mute_end_timestamp = 5678
    patch_bytes = _build_patch(
        version=110,
        prev_hash=_ZERO,
        index=["mute", "555@s.whatsapp.net"],
        action=action,
    )

    async with FakeWhatsAppServer() as server:
        server.app_state_patches[_NAME] = [patch_bytes]
        client = Client(session_path=session_path, ws_url=server.url)
        events: list[object] = []

        @client.on("mute")
        async def _on_mute(evt: object) -> None:
            events.append(evt)

        await _connect(client, server)
        await server.deliver_server_sync([(_NAME, 110)])
        await poll_until(lambda: bool(events), timeout_s=5.0)
        await client.disconnect()

    assert len(events) == 1
    from pywhats.events import Mute

    evt = events[0]
    assert isinstance(evt, Mute)
    assert evt.jid.user == "555"
    assert evt.muted is True
    assert evt.mute_end_timestamp == 5678
    assert evt.timestamp == 1234


def _persisted_version(session_path: str) -> int:
    store = SqliteStore(f"{session_path}.signal.db")
    try:
        return store.app_state.get_version(_NAME).version
    finally:
        store.close()
