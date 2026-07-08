# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Decode and verify a ``SyncdPatch`` into app-state mutations (issue #35b).

A patch is a signed, ordered batch of SET/REMOVE mutations against one
collection. Decoding it means: fold every mutation into the running
LT-hash, check the collection's snapshot MAC and the patch MAC against
the new hash, then — per mutation — verify the content MAC, AES-CBC
decrypt the value, and verify the index MAC. Any tampering trips a
:class:`MacMismatch`.

Mirrors whatsmeow ``appstate/decode.go`` (``validatePatch`` +
``decodeMutations`` + ``decodeMutation``) and ``appstate/hash.go``
(``updateHash`` / ``generateSnapshotMAC`` / ``generatePatchMAC``). The
per-mutation key is resolved from the #35a
:class:`~pywhats.appstate.AppStateKeyStore`.

Scope note: this decodes a single already-parsed patch. Fetching the
``w:sync:app:state`` iq, walking the version cursor, and persisting the
per-collection hash + mutation MACs are #35c; surfacing the decoded
actions as events is #35d.
"""

from __future__ import annotations

import hmac as _hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256

from pywhats.appstate.crypto import (
    ExpandedAppStateKeys,
    aes_cbc_decrypt,
    expand_app_state_keys,
    generate_content_mac,
)
from pywhats.appstate.keys import AppStateKeyStore
from pywhats.appstate.lthash import subtract_then_add
from pywhats.proto import SyncActionData
from pywhats.proto import SyncdMutation as _SyncdMutation

__all__ = [
    "AppStateError",
    "AppStateKeyNotFound",
    "MacMismatch",
    "ContentMacMismatch",
    "IndexMacMismatch",
    "SnapshotMacMismatch",
    "PatchMacMismatch",
    "HashState",
    "Mutation",
    "PatchDecodeResult",
    "decode_patch",
    "decode_snapshot",
]

_SET = 0
_REMOVE = 1


class AppStateError(Exception):
    """Base for app-state decode failures."""


class AppStateKeyNotFound(AppStateError):
    """The key id a patch references has not been received/stored."""


class MacMismatch(AppStateError):
    """An authentication tag did not verify — the patch is untrusted."""


class ContentMacMismatch(MacMismatch):
    pass


class IndexMacMismatch(MacMismatch):
    pass


class SnapshotMacMismatch(MacMismatch):
    pass


class PatchMacMismatch(MacMismatch):
    pass


@dataclass(frozen=True)
class HashState:
    """A collection's sync cursor: its version and 128-byte LT-hash."""

    version: int = 0
    hash: bytes = field(default=b"\x00" * 128)


# The empty starting cursor (version 0, all-zero hash). A module-level
# singleton because HashState is frozen, so it can be shared as a default.
_EMPTY_STATE = HashState()


@dataclass(frozen=True)
class Mutation:
    """One decoded mutation and the MACs it contributes to the LT-hash."""

    operation: int
    index: list[str]
    action: object  # SyncActionValue
    index_mac: bytes
    value_mac: bytes
    key_id: bytes
    version: int


@dataclass(frozen=True)
class PatchDecodeResult:
    state: HashState
    mutations: list[Mutation]


PrevValueMac = Callable[[bytes], bytes | None]


def _resolve_keys(store: AppStateKeyStore, key_id: bytes) -> ExpandedAppStateKeys:
    key = store.get(key_id)
    if key is None:
        raise AppStateKeyNotFound(f"no app-state sync key for id {key_id.hex()}")
    return expand_app_state_keys(key.key_data)


def _update_hash(
    prev_hash: bytes,
    mutations: list[_SyncdMutation],
    get_prev_value_mac: PrevValueMac | None,
) -> bytes:
    """Fold the patch's mutations into the LT-hash (whatsmeow updateHash).

    A SET contributes its value MAC as an *add*. Any mutation that
    replaces a prior value for the same index contributes that prior
    value MAC as a *subtract* — found either earlier in this same patch
    or, failing that, via ``get_prev_value_mac`` (the stored DB state).
    """
    added: list[bytes] = []
    removed: list[bytes] = []
    for i, mutation in enumerate(mutations):
        blob = mutation.record.value.blob
        if mutation.operation == _SET:
            added.append(blob[-32:])
        index_mac = mutation.record.index.blob
        prev = _prev_set_value_mac(mutations, i, index_mac, get_prev_value_mac)
        if prev is not None:
            removed.append(prev)
    return subtract_then_add(prev_hash, added=added, removed=removed)


def _prev_set_value_mac(
    mutations: list[_SyncdMutation],
    max_index: int,
    index_mac: bytes,
    get_prev_value_mac: PrevValueMac | None,
) -> bytes | None:
    # Search earlier mutations in this patch (newest first) for the same
    # index; a prior SET's value MAC is the value being replaced.
    for j in range(max_index - 1, -1, -1):
        if _hmac.compare_digest(mutations[j].record.index.blob, index_mac):
            if mutations[j].operation == _SET:
                return bytes(mutations[j].record.value.blob[-32:])
            return None
    # Not in this patch — fall back to previously stored DB state.
    if get_prev_value_mac is not None:
        return get_prev_value_mac(index_mac)
    return None


def decode_patch(
    patch: object,
    key_store: AppStateKeyStore,
    name: str,
    prev_state: HashState,
    *,
    get_prev_value_mac: PrevValueMac | None = None,
    validate_macs: bool = True,
) -> PatchDecodeResult:
    """Decode and verify ``patch`` for collection ``name``.

    Raises :class:`AppStateKeyNotFound` if the referenced key is unknown,
    or a :class:`MacMismatch` subclass if any layer fails to
    authenticate. Returns the advanced :class:`HashState` and the ordered
    decoded mutations.
    """
    mutations = list(patch.mutations)  # type: ignore[attr-defined]
    version = int(patch.version.version)  # type: ignore[attr-defined]
    keys = _resolve_keys(key_store, patch.key_id.id)  # type: ignore[attr-defined]

    new_hash = _update_hash(prev_state.hash, mutations, get_prev_value_mac)
    new_state = HashState(version=version, hash=new_hash)

    if validate_macs:
        _verify_snapshot_mac(new_state, name, keys.snapshot_mac, patch.snapshot_mac)  # type: ignore[attr-defined]
        _verify_patch_mac(patch, name, keys.patch_mac, version)

    decoded = [_decode_mutation(m, key_store, validate_macs=validate_macs) for m in mutations]
    return PatchDecodeResult(state=new_state, mutations=decoded)


def decode_snapshot(
    snapshot: object,
    key_store: AppStateKeyStore,
    name: str,
    initial_state: HashState = _EMPTY_STATE,
    *,
    validate_macs: bool = True,
) -> PatchDecodeResult:
    """Decode and verify a full ``SyncdSnapshot`` for collection ``name``.

    Mirrors whatsmeow ``Processor.decodeSnapshot`` (appstate/decode.go): a
    snapshot is a fresh full state, so every record is a SET whose value
    MAC is *added* to the LT-hash with no prior value to subtract (its
    ``getPrevSetValueMAC`` callback returns nil unconditionally — unlike a
    patch, it never dedups within the snapshot). The resulting hash is
    checked against the snapshot MAC, then each record is decrypted.
    """
    records = list(snapshot.records)  # type: ignore[attr-defined]
    version = int(snapshot.version.version)  # type: ignore[attr-defined]
    mutations = [_SyncdMutation(operation=_SET, record=r) for r in records]

    added = [bytes(m.record.value.blob[-32:]) for m in mutations]
    new_hash = subtract_then_add(initial_state.hash, added=added, removed=[])
    new_state = HashState(version=version, hash=new_hash)

    if validate_macs:
        keys = _resolve_keys(key_store, snapshot.key_id.id)  # type: ignore[attr-defined]
        _verify_snapshot_mac(new_state, name, keys.snapshot_mac, snapshot.mac)  # type: ignore[attr-defined]

    decoded = [_decode_mutation(m, key_store, validate_macs=validate_macs) for m in mutations]
    return PatchDecodeResult(state=new_state, mutations=decoded)


def _verify_snapshot_mac(
    state: HashState, name: str, snapshot_mac_key: bytes, expected: bytes
) -> None:
    mac = _hmac.new(
        snapshot_mac_key,
        state.hash + state.version.to_bytes(8, "big") + name.encode(),
        sha256,
    ).digest()
    if not _hmac.compare_digest(mac, expected):
        raise SnapshotMacMismatch(f"snapshot MAC mismatch for {name} v{state.version}")


def _verify_patch_mac(patch: object, name: str, patch_mac_key: bytes, version: int) -> None:
    h = _hmac.new(patch_mac_key, patch.snapshot_mac, sha256)  # type: ignore[attr-defined]
    for mutation in patch.mutations:  # type: ignore[attr-defined]
        h.update(mutation.record.value.blob[-32:])
    h.update(version.to_bytes(8, "big"))
    h.update(name.encode())
    if not _hmac.compare_digest(h.digest(), patch.patch_mac):  # type: ignore[attr-defined]
        raise PatchMacMismatch(f"patch MAC mismatch for {name} v{version}")


def _decode_mutation(
    mutation: _SyncdMutation, key_store: AppStateKeyStore, *, validate_macs: bool
) -> Mutation:
    key_id = bytes(mutation.record.key_id.id)
    keys = _resolve_keys(key_store, key_id)
    blob = bytes(mutation.record.value.blob)
    content, value_mac = blob[:-32], blob[-32:]
    operation = mutation.operation

    if validate_macs:
        expected = generate_content_mac(
            operation=operation, data=content, key_id=key_id, value_mac_key=keys.value_mac
        )
        if not _hmac.compare_digest(expected, value_mac):
            raise ContentMacMismatch("mutation content MAC mismatch")

    plaintext = aes_cbc_decrypt(keys.value_encryption, content)
    action_data = SyncActionData()
    action_data.ParseFromString(plaintext)

    index_mac = bytes(mutation.record.index.blob)
    if validate_macs:
        expected_index = _hmac.new(keys.index, action_data.index, sha256).digest()
        if not _hmac.compare_digest(expected_index, index_mac):
            raise IndexMacMismatch("mutation index MAC mismatch")

    index_list: list[str] = json.loads(action_data.index)
    return Mutation(
        operation=operation,
        index=index_list,
        action=action_data.value,
        index_mac=index_mac,
        value_mac=value_mac,
        key_id=key_id,
        version=int(action_data.version),
    )
