# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Fixture tests for SyncdPatch decode (issue #35b).

Each test builds a well-formed ``SyncdPatch`` the way the phone would
(encrypt the SyncActionData, MAC every layer), then decodes it and
asserts the recovered mutation and the resulting LT-hash state. The
crypto primitives are already pinned by known-answer tests in
``test_appstate_crypto.py``; these exercise the decode orchestration —
MAC ordering, SET/REMOVE routing, within-patch dedup, and the error
paths — mirroring whatsmeow ``appstate/decode.go`` + ``hash.go``.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.appstate import AppStateSyncKey, InMemoryAppStateKeyStore
from pywhats.appstate.crypto import expand_app_state_keys
from pywhats.appstate.lthash import subtract_then_add
from pywhats.appstate.patches import (
    AppStateKeyNotFound,
    ContentMacMismatch,
    HashState,
    IndexMacMismatch,
    PatchMacMismatch,
    SnapshotMacMismatch,
    decode_patch,
    decode_snapshot,
)
from pywhats.proto import (
    KeyId,
    SyncActionData,
    SyncActionValue,
    SyncdIndex,
    SyncdMutation,
    SyncdPatch,
    SyncdRecord,
    SyncdSnapshot,
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
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _build_mutation(
    *, operation: int, index: list[str], timestamp: int, iv: bytes = b"\x00" * 16
) -> tuple[SyncdMutation, bytes]:
    """Return a ``SyncdMutation`` and the 32-byte value MAC (the LT-hash item)."""
    keys = expand_app_state_keys(_KEY_DATA)
    index_json = json.dumps(index, separators=(",", ":")).encode()
    action = SyncActionValue(timestamp=timestamp)
    plaintext = SyncActionData(index=index_json, value=action, version=3).SerializeToString()
    content = iv + _pkcs7_encrypt(keys.value_encryption, iv, plaintext)
    # generate_content_mac: HMAC-SHA512(value_mac_key, op+1 || key_id || content
    # || be8(len(key_id)+1))[:32] — whatsmeow appstate/hash.go generateContentMAC.
    mac_input = bytes([operation + 1]) + _KEY_ID + content + (len(_KEY_ID) + 1).to_bytes(8, "big")
    value_mac = hmac.new(keys.value_mac, mac_input, hashlib.sha512).digest()[:32]
    index_mac = hmac.new(keys.index, index_json, hashlib.sha256).digest()
    record = SyncdRecord(
        index=SyncdIndex(blob=index_mac),
        value=SyncdValue(blob=content + value_mac),
        key_id=KeyId(id=_KEY_ID),
    )
    return SyncdMutation(operation=operation, record=record), value_mac


def _finalize_patch(patch: SyncdPatch, *, version: int, new_hash: bytes) -> SyncdPatch:
    keys = expand_app_state_keys(_KEY_DATA)
    snapshot_mac = hmac.new(
        keys.snapshot_mac,
        new_hash + version.to_bytes(8, "big") + _NAME.encode(),
        hashlib.sha256,
    ).digest()
    # generatePatchMAC: HMAC-SHA256(patch_mac_key, snapshot_mac || each value[-32:]
    # || be8(version) || name) — whatsmeow appstate/hash.go generatePatchMAC.
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


def _build_snapshot(*, version: int, indexes: list[list[str]]) -> tuple[SyncdSnapshot, bytes]:
    """Build a well-formed ``SyncdSnapshot`` of SET records; return it + final hash."""
    records = []
    added: list[bytes] = []
    for i, index in enumerate(indexes):
        mut, vmac = _build_mutation(operation=0, index=index, timestamp=100 + i, iv=bytes([i]) * 16)
        records.append(mut.record)
        added.append(vmac)
    final_hash = subtract_then_add(_ZERO, added=added, removed=[])
    keys = expand_app_state_keys(_KEY_DATA)
    mac = hmac.new(
        keys.snapshot_mac,
        final_hash + version.to_bytes(8, "big") + _NAME.encode(),
        hashlib.sha256,
    ).digest()
    snapshot = SyncdSnapshot(
        version={"version": version}, records=records, mac=mac, key_id=KeyId(id=_KEY_ID)
    )
    return snapshot, final_hash


def test_decode_snapshot_recovers_all_sets_and_hash() -> None:
    snapshot, final_hash = _build_snapshot(
        version=153, indexes=[["mute", "a@s"], ["pin", "b@s"], ["contact", "c@s"]]
    )
    result = decode_snapshot(snapshot, _key_store(), _NAME)

    assert result.state.version == 153
    assert result.state.hash == final_hash
    assert [m.index[0] for m in result.mutations] == ["mute", "pin", "contact"]
    assert all(m.operation == SyncdMutation.SET for m in result.mutations)


def test_decode_snapshot_corrupt_mac_raises() -> None:
    snapshot, _ = _build_snapshot(version=5, indexes=[["mute", "a@s"]])
    snapshot.mac = bytes(32)
    with pytest.raises(SnapshotMacMismatch):
        decode_snapshot(snapshot, _key_store(), _NAME)


def test_decode_snapshot_unknown_key_raises() -> None:
    snapshot, _ = _build_snapshot(version=5, indexes=[["mute", "a@s"]])
    with pytest.raises(AppStateKeyNotFound):
        decode_snapshot(snapshot, InMemoryAppStateKeyStore(), _NAME)


def test_decode_single_set_recovers_action_and_advances_hash() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "123@s.whatsapp.net"], timestamp=999)
    patch = SyncdPatch(mutations=[mut])
    new_hash = subtract_then_add(_ZERO, added=[vmac], removed=[])
    _finalize_patch(patch, version=5, new_hash=new_hash)

    result = decode_patch(patch, _key_store(), _NAME, HashState())

    assert result.state.version == 5
    assert result.state.hash == new_hash
    assert len(result.mutations) == 1
    m = result.mutations[0]
    assert m.operation == SyncdMutation.SET
    assert m.index == ["mute", "123@s.whatsapp.net"]
    assert m.action.timestamp == 999


def test_decode_set_then_remove_same_index_returns_hash_to_base() -> None:
    set_mut, _ = _build_mutation(operation=0, index=["pin", "a@s"], timestamp=1)
    rm_mut, _ = _build_mutation(operation=1, index=["pin", "a@s"], timestamp=2, iv=b"\x11" * 16)
    patch = SyncdPatch(mutations=[set_mut, rm_mut])
    _finalize_patch(patch, version=6, new_hash=_ZERO)

    result = decode_patch(patch, _key_store(), _NAME, HashState())

    assert result.state.hash == _ZERO
    assert [m.operation for m in result.mutations] == [SyncdMutation.SET, SyncdMutation.REMOVE]


def test_decode_two_sets_same_index_dedups_to_latest_value() -> None:
    first, _ = _build_mutation(operation=0, index=["contact", "x@s"], timestamp=1)
    second, vmac2 = _build_mutation(
        operation=0, index=["contact", "x@s"], timestamp=2, iv=b"\x22" * 16
    )
    patch = SyncdPatch(mutations=[first, second])
    # Net LT-hash is the latest value only — the first is subtracted back out.
    new_hash = subtract_then_add(_ZERO, added=[vmac2], removed=[])
    _finalize_patch(patch, version=7, new_hash=new_hash)

    result = decode_patch(patch, _key_store(), _NAME, HashState())
    assert result.state.hash == new_hash


def test_decode_remove_uses_prev_value_mac_from_store() -> None:
    # Prior SET of this index is in the DB (not this patch); the REMOVE
    # must look its value MAC up to subtract it (whatsmeow updateHash's
    # getPrevSetValueMAC DB fallback).
    set_mut, vmac = _build_mutation(operation=0, index=["archive", "y@s"], timestamp=1)
    prev_hash = subtract_then_add(_ZERO, added=[vmac], removed=[])
    index_mac = set_mut.record.index.blob

    rm_mut, _ = _build_mutation(operation=1, index=["archive", "y@s"], timestamp=2)
    patch = SyncdPatch(mutations=[rm_mut])
    _finalize_patch(patch, version=8, new_hash=_ZERO)

    def prev_lookup(imac: bytes) -> bytes | None:
        return vmac if imac == index_mac else None

    result = decode_patch(
        patch,
        _key_store(),
        _NAME,
        HashState(version=7, hash=prev_hash),
        get_prev_value_mac=prev_lookup,
    )
    assert result.state.hash == _ZERO


def test_decode_unknown_key_id_raises() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "z@s"], timestamp=1)
    patch = SyncdPatch(mutations=[mut])
    _finalize_patch(patch, version=5, new_hash=subtract_then_add(_ZERO, added=[vmac], removed=[]))

    empty = InMemoryAppStateKeyStore()
    with pytest.raises(AppStateKeyNotFound):
        decode_patch(patch, empty, _NAME, HashState())


def test_decode_corrupt_value_mac_raises() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "z@s"], timestamp=1)
    patch = SyncdPatch(mutations=[mut])
    _finalize_patch(patch, version=5, new_hash=subtract_then_add(_ZERO, added=[vmac], removed=[]))
    # Flip a byte inside the value blob's ciphertext (not the trailing MAC).
    blob = bytearray(patch.mutations[0].record.value.blob)
    blob[20] ^= 0xFF
    patch.mutations[0].record.value.blob = bytes(blob)
    with pytest.raises(ContentMacMismatch):
        decode_patch(patch, _key_store(), _NAME, HashState())


def test_decode_corrupt_index_mac_raises() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "z@s"], timestamp=1)
    patch = SyncdPatch(mutations=[mut])
    _finalize_patch(patch, version=5, new_hash=subtract_then_add(_ZERO, added=[vmac], removed=[]))
    bad = bytearray(patch.mutations[0].record.index.blob)
    bad[0] ^= 0xFF
    patch.mutations[0].record.index.blob = bytes(bad)
    with pytest.raises(IndexMacMismatch):
        decode_patch(patch, _key_store(), _NAME, HashState())


def test_decode_corrupt_snapshot_mac_raises() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "z@s"], timestamp=1)
    patch = SyncdPatch(mutations=[mut])
    _finalize_patch(patch, version=5, new_hash=subtract_then_add(_ZERO, added=[vmac], removed=[]))
    patch.snapshot_mac = bytes(32)
    with pytest.raises(SnapshotMacMismatch):
        decode_patch(patch, _key_store(), _NAME, HashState())


def test_decode_corrupt_patch_mac_raises() -> None:
    mut, vmac = _build_mutation(operation=0, index=["mute", "z@s"], timestamp=1)
    patch = SyncdPatch(mutations=[mut])
    _finalize_patch(patch, version=5, new_hash=subtract_then_add(_ZERO, added=[vmac], removed=[]))
    patch.patch_mac = bytes(32)
    with pytest.raises(PatchMacMismatch):
        decode_patch(patch, _key_store(), _NAME, HashState())
