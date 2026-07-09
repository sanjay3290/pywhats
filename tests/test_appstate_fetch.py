# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Fetch + apply orchestration for app-state sync (issue #35c).

Covers the pure pieces that turn a ``w:sync:app:state`` collection node
into persisted state: the fetch-iq content builder, the binary-node patch
parser, and the apply loop that threads the LT-hash cursor and persists
version + mutation MACs. Mirrors whatsmeow ``appstate.go`` (fetchAppState /
fetchAppStatePatches) + ``appstate/decode.go`` (ParsePatchList /
DecodePatches).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.appstate import AppStateSyncKey, InMemoryAppStateKeyStore
from pywhats.appstate.crypto import expand_app_state_keys
from pywhats.appstate.fetch import (
    AppStateSyncer,
    apply_patch_list,
    build_fetch_collection_content,
    parse_patch_list,
)
from pywhats.appstate.lthash import subtract_then_add
from pywhats.appstate.patches import HashState
from pywhats.appstate.store import InMemoryAppStateStore
from pywhats.binary import Node
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

_NAME = "regular_low"
_KEY_ID = b"\x00\x00\x2a"
_KEY_DATA = bytes(range(32, 64))
_ZERO = b"\x00" * 128


def _key_store() -> InMemoryAppStateKeyStore:
    store = InMemoryAppStateKeyStore()
    store.put(AppStateSyncKey(key_id=_KEY_ID, key_data=_KEY_DATA, fingerprint=b"fp", timestamp=1))
    return store


def _pkcs7_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(plaintext + bytes([pad]) * pad) + enc.finalize()


def _mutation(*, operation: int, index: list[str], iv: bytes) -> tuple[SyncdMutation, bytes]:
    keys = expand_app_state_keys(_KEY_DATA)
    index_json = json.dumps(index, separators=(",", ":")).encode()
    action = SyncActionValue(timestamp=1)
    plaintext = SyncActionData(index=index_json, value=action, version=3).SerializeToString()
    content = iv + _pkcs7_encrypt(keys.value_encryption, iv, plaintext)
    mac_input = bytes([operation + 1]) + _KEY_ID + content + (len(_KEY_ID) + 1).to_bytes(8, "big")
    value_mac = hmac.new(keys.value_mac, mac_input, hashlib.sha512).digest()[:32]
    index_mac = hmac.new(keys.index, index_json, hashlib.sha256).digest()
    record = SyncdRecord(
        index=SyncdIndex(blob=index_mac),
        value=SyncdValue(blob=content + value_mac),
        key_id=KeyId(id=_KEY_ID),
    )
    return SyncdMutation(operation=operation, record=record), value_mac


def _finalize(patch: SyncdPatch, *, version: int, new_hash: bytes) -> SyncdPatch:
    keys = expand_app_state_keys(_KEY_DATA)
    snapshot_mac = hmac.new(
        keys.snapshot_mac,
        new_hash + version.to_bytes(8, "big") + _NAME.encode(),
        hashlib.sha256,
    ).digest()
    h = hmac.new(keys.patch_mac, snapshot_mac, hashlib.sha256)
    for m in patch.mutations:
        h.update(m.record.value.blob[-32:])
    h.update(version.to_bytes(8, "big"))
    h.update(_NAME.encode())
    patch.snapshot_mac = snapshot_mac
    patch.patch_mac = h.digest()
    patch.key_id.id = _KEY_ID
    patch.version.version = version
    return patch


def _one_patch_collection(*, version: int, has_more: bool = False) -> tuple[Node, bytes]:
    mut, vmac = _mutation(operation=0, index=["mute", "x@s"], iv=b"\x00" * 16)
    patch = SyncdPatch(mutations=[mut])
    new_hash = subtract_then_add(_ZERO, added=[vmac], removed=[])
    _finalize(patch, version=version, new_hash=new_hash)
    attrs: dict[str, str | int] = {"name": _NAME}
    if has_more:
        attrs["has_more_patches"] = "true"
    collection = Node(
        tag="collection",
        attrs=attrs,
        content=[
            Node(
                tag="patches",
                content=[Node(tag="patch", content=patch.SerializeToString())],
            )
        ],
    )
    return collection, new_hash


# --- build_fetch_collection_content ----------------------------------


def test_fetch_content_for_snapshot_omits_version() -> None:
    node = build_fetch_collection_content(_NAME, version=0, want_snapshot=True)
    collection = node.get_child("collection")
    assert collection is not None
    assert collection.get_str("name") == _NAME
    assert collection.get_str("return_snapshot") == "true"
    assert "version" not in collection.attrs


def test_fetch_content_for_patches_includes_version() -> None:
    node = build_fetch_collection_content(_NAME, version=153, want_snapshot=False)
    collection = node.get_child("collection")
    assert collection is not None
    assert collection.get_str("version") == "153"
    assert collection.get_str("return_snapshot") == "false"


# --- parse_patch_list ------------------------------------------------


@pytest.mark.asyncio
async def test_parse_patch_list_reads_inline_patches() -> None:
    collection, _ = _one_patch_collection(version=110, has_more=True)
    patch_list = await parse_patch_list(collection, download_external=None)
    assert patch_list.name == _NAME
    assert patch_list.has_more_patches is True
    assert patch_list.snapshot is None
    assert len(patch_list.patches) == 1
    assert patch_list.patches[0].version.version == 110


@pytest.mark.asyncio
async def test_parse_patch_list_external_snapshot_without_downloader_raises() -> None:
    collection = Node(
        tag="collection",
        attrs={"name": _NAME},
        content=[Node(tag="snapshot", content=b"\x0a\x02\x08\x01")],
    )
    with pytest.raises(ValueError, match="download"):
        await parse_patch_list(collection, download_external=None)


# --- apply_patch_list ------------------------------------------------


@pytest.mark.asyncio
async def test_apply_one_patch_persists_version_and_mac() -> None:
    collection, new_hash = _one_patch_collection(version=110)
    patch_list = await parse_patch_list(collection, download_external=None)
    app_state = InMemoryAppStateStore()

    mutations, state = apply_patch_list(patch_list, _key_store(), app_state, HashState())

    assert state.version == 110
    assert state.hash == new_hash
    assert app_state.get_version(_NAME).version == 110
    assert app_state.get_version(_NAME).hash == new_hash
    # The SET's value MAC is stored for later prev-value lookups.
    assert len(mutations) == 1
    index_mac = mutations[0].index_mac
    assert app_state.get_mutation_mac(_NAME, index_mac) == mutations[0].value_mac


@pytest.mark.asyncio
async def test_apply_remove_uses_stored_prev_mac_and_deletes_it() -> None:
    # A prior SET is on record (in the store); a REMOVE patch must find its
    # value MAC to subtract it back out and then drop the row.
    set_mut, vmac = _mutation(operation=0, index=["archive", "y@s"], iv=b"\x00" * 16)
    index_mac = set_mut.record.index.blob
    prev_hash = subtract_then_add(_ZERO, added=[vmac], removed=[])

    app_state = InMemoryAppStateStore()
    from pywhats.appstate.store import MutationMac

    app_state.put_version(_NAME, HashState(version=1, hash=prev_hash))
    app_state.put_mutation_macs(_NAME, 1, [MutationMac(index_mac, vmac)])

    rm_mut, _ = _mutation(operation=1, index=["archive", "y@s"], iv=b"\x11" * 16)
    patch = SyncdPatch(mutations=[rm_mut])
    _finalize(patch, version=2, new_hash=_ZERO)
    collection = Node(
        tag="collection",
        attrs={"name": _NAME},
        content=[
            Node(tag="patches", content=[Node(tag="patch", content=patch.SerializeToString())])
        ],
    )
    patch_list = await parse_patch_list(collection, download_external=None)

    _, state = apply_patch_list(patch_list, _key_store(), app_state, app_state.get_version(_NAME))

    assert state.hash == _ZERO
    assert state.version == 2
    assert app_state.get_mutation_mac(_NAME, index_mac) is None


# --- AppStateSyncer: missing sync key on fresh pair -------------------


class _NoopTransport:
    async def send(self, plaintext: bytes) -> None:
        pass


class _CannedIqMap:
    """Resolves every registered iq immediately with a canned response."""

    def __init__(self, response: Node) -> None:
        self._response = response

    def register(self, iq_id: str) -> asyncio.Future[Node]:
        fut: asyncio.Future[Node] = asyncio.get_event_loop().create_future()
        fut.set_result(self._response)
        return fut

    def cancel(self, iq_id: str) -> None:
        pass


def _syncer_with_keyless_collection() -> AppStateSyncer:
    """A syncer whose server returns a patch referencing an unknown key."""
    collection, _ = _one_patch_collection(version=1)
    response = Node(
        tag="iq",
        attrs={"type": "result"},
        content=[Node(tag="sync", content=[collection])],
    )
    return AppStateSyncer(
        transport=_NoopTransport(),
        iq_map=_CannedIqMap(response),
        key_store=InMemoryAppStateKeyStore(),  # deliberately empty
        app_state_store=InMemoryAppStateStore(),
    )


@pytest.mark.asyncio
async def test_fetch_with_missing_key_warns_and_returns_empty(caplog) -> None:
    """On a fresh pair the sync keys may not have arrived yet; a missing
    key must not raise — just a single warning and an empty result."""
    syncer = _syncer_with_keyless_collection()
    with caplog.at_level(logging.WARNING, logger="pywhats.appstate.fetch"):
        mutations = await syncer.fetch(_NAME)
    assert mutations == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "key" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_server_sync_with_missing_key_logs_no_traceback(caplog) -> None:
    syncer = _syncer_with_keyless_collection()
    notification = Node(
        tag="notification",
        attrs={"type": "server_sync"},
        content=[Node(tag="collection", attrs={"name": _NAME})],
    )
    with caplog.at_level(logging.DEBUG, logger="pywhats.appstate.fetch"):
        await syncer.handle_server_sync(notification)
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)
    assert not any(r.exc_info for r in caplog.records)
