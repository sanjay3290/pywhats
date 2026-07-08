# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Fetch and apply app-state collection patches (issue #35c).

This is the live half of app-state sync: given a collection name and the
version cursor stored from the last sync, send a
``<iq to="s.whatsapp.net" type="set" xmlns="w:sync:app:state">`` asking
for the snapshot (full sync) or the patches since that version, parse the
``SyncdSnapshot`` / ``SyncdPatch`` protos out of the binary response
nodes, run the #35b decode primitives over them while threading the
LT-hash cursor, and persist the advanced version + hash + the per-index
mutation MACs.

The server drives this: after linking (and whenever app state changes) it
pushes ``<notification type="server_sync"><collection name= version=>``.
:meth:`AppStateSyncer.handle_server_sync` reacts to that notification by
fetching each advertised collection from the stored cursor.

Mirrors whatsmeow ``appstate.go`` (``fetchAppState`` /
``fetchAppStatePatches`` / ``applyAppStatePatches`` /
``handleAppStateNotification``) and ``appstate/decode.go``
(``ParsePatchList`` / ``DecodePatches``).

Snapshots (and oversized patches) arrive as an ``ExternalBlobReference``
that must be downloaded from the media CDN and decrypted — that media
primitive is #36. Until it is wired in, ``download_external`` is ``None``
and an external blob raises a clear error rather than silently dropping
state; inline incremental patches (the common ``server_sync`` case) need
no downloader.
"""

from __future__ import annotations

import hmac as _hmac
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from pywhats.appstate.keys import AppStateKeyStore
from pywhats.appstate.patches import (
    HashState,
    Mutation,
    decode_patch,
    decode_snapshot,
)
from pywhats.appstate.store import AppStateStore, MutationMac
from pywhats.binary import Node, encode
from pywhats.events import JID
from pywhats.messaging.ids import new_message_id
from pywhats.proto import ExternalBlobReference as _ExternalBlobReference
from pywhats.proto import SyncdMutations as _SyncdMutations
from pywhats.proto import SyncdPatch as _SyncdPatch
from pywhats.proto import SyncdSnapshot as _SyncdSnapshot

__all__ = [
    "PatchList",
    "DownloadExternal",
    "build_fetch_collection_content",
    "parse_patch_list",
    "apply_patch_list",
    "AppStateSyncer",
]

_log = logging.getLogger("pywhats.appstate.fetch")

_SET = 0
_REMOVE = 1
_SERVER = JID(user="", server="s.whatsapp.net")
_XMLNS = "w:sync:app:state"

# Downloads and decrypts an external app-state blob, returning its plaintext
# protobuf bytes (a serialized SyncdSnapshot or SyncdMutations). Implemented
# by the media layer in #36.
DownloadExternal = Callable[["_ExternalBlobReference"], Awaitable[bytes]]


@dataclass(frozen=True)
class PatchList:
    """A parsed ``w:sync:app:state`` collection response."""

    name: str
    has_more_patches: bool = False
    patches: list[object] = field(default_factory=list)
    snapshot: object | None = None


# --- iq content ------------------------------------------------------


def build_fetch_collection_content(name: str, version: int, want_snapshot: bool) -> Node:
    """Build the ``<sync><collection>`` body of the fetch iq.

    whatsmeow ``fetchAppStatePatches``: ``return_snapshot`` toggles a full
    resync; ``version`` is only sent when asking for incremental patches.
    """
    attrs: dict[str, str | int | JID] = {
        "name": name,
        "return_snapshot": "true" if want_snapshot else "false",
    }
    if not want_snapshot:
        attrs["version"] = str(version)
    return Node(tag="sync", content=[Node(tag="collection", attrs=attrs)])


# --- parse -----------------------------------------------------------


async def parse_patch_list(
    collection: Node, download_external: DownloadExternal | None
) -> PatchList:
    """Decode the ``SyncdSnapshot`` / ``SyncdPatch`` protos from a collection node.

    Mirrors whatsmeow ``ParsePatchList``: an external snapshot blob and any
    oversized patch's ``external_mutations`` are downloaded and their
    protobufs spliced back in.
    """
    snapshot = await _parse_snapshot(collection, download_external)
    patches = await _parse_patches(collection, download_external)
    return PatchList(
        name=collection.get_str("name"),
        has_more_patches=_attr_bool(collection, "has_more_patches"),
        patches=patches,
        snapshot=snapshot,
    )


def _attr_bool(node: Node, name: str) -> bool:
    return node.get_str(name).lower() in ("true", "1")


async def _parse_snapshot(
    collection: Node, download_external: DownloadExternal | None
) -> object | None:
    snapshot_node = collection.get_child("snapshot")
    if snapshot_node is None:
        return None
    raw = snapshot_node.content_bytes()
    if not raw:
        return None
    ref = _ExternalBlobReference()
    ref.ParseFromString(raw)
    if download_external is None:
        raise ValueError(
            "app-state snapshot is an external blob; a media downloader (#36) is required"
        )
    data = await download_external(ref)
    snapshot: object = _SyncdSnapshot()
    snapshot.ParseFromString(data)  # type: ignore[attr-defined]
    return snapshot


async def _parse_patches(
    collection: Node, download_external: DownloadExternal | None
) -> list[object]:
    patches_node = collection.get_child("patches")
    if patches_node is None:
        return []
    patches: list[object] = []
    for patch_node in patches_node.get_children("patch"):
        raw = patch_node.content_bytes()
        if not raw:
            continue
        patch = _SyncdPatch()
        patch.ParseFromString(raw)
        if patch.HasField("external_mutations"):
            if download_external is None:
                raise ValueError(
                    "app-state patch has external mutations; a media downloader (#36) is required"
                )
            data = await download_external(patch.external_mutations)
            downloaded = _SyncdMutations()
            downloaded.ParseFromString(data)
            del patch.mutations[:]
            patch.mutations.extend(downloaded.mutations)
        patches.append(patch)
    return patches


# --- apply -----------------------------------------------------------


def _compute_mac_deltas(mutations: list[Mutation]) -> tuple[list[MutationMac], list[bytes]]:
    """Split decoded mutations into the MACs to add vs. remove from the store.

    Mirrors whatsmeow ``patchOutput`` (decode.go): a SET adds its
    (index, value) MAC; a REMOVE drops that index and cancels any add for
    the same index earlier in this patch.
    """
    added: list[MutationMac] = []
    removed: list[bytes] = []
    for mutation in mutations:
        if mutation.operation == _REMOVE:
            removed.append(mutation.index_mac)
            added = [a for a in added if not _hmac.compare_digest(a.index_mac, mutation.index_mac)]
        elif mutation.operation == _SET:
            added.append(MutationMac(index_mac=mutation.index_mac, value_mac=mutation.value_mac))
    return added, removed


def apply_patch_list(
    patch_list: PatchList,
    key_store: AppStateKeyStore,
    app_state_store: AppStateStore,
    initial_state: HashState,
    *,
    validate_macs: bool = True,
) -> tuple[list[Mutation], HashState]:
    """Decode every snapshot/patch in ``patch_list``, persisting as it goes.

    Threads the LT-hash cursor through the snapshot (if any) then each
    patch in order, and after each one persists the advanced version +
    hash and the added/removed mutation MACs — exactly the ``storeMACs``
    ordering in whatsmeow ``DecodePatches``. Returns the decoded mutations
    and the final :class:`HashState`.
    """
    name = patch_list.name
    state = initial_state
    all_mutations: list[Mutation] = []

    if patch_list.snapshot is not None:
        result = decode_snapshot(
            patch_list.snapshot, key_store, name, state, validate_macs=validate_macs
        )
        _persist(app_state_store, name, result.state, result.mutations)
        all_mutations.extend(result.mutations)
        state = result.state

    for patch in patch_list.patches:

        def _prev(index_mac: bytes, _name: str = name) -> bytes | None:
            return app_state_store.get_mutation_mac(_name, index_mac)

        result = decode_patch(
            patch,
            key_store,
            name,
            state,
            get_prev_value_mac=_prev,
            validate_macs=validate_macs,
        )
        _persist(app_state_store, name, result.state, result.mutations)
        all_mutations.extend(result.mutations)
        state = result.state

    return all_mutations, state


def _persist(
    app_state_store: AppStateStore, name: str, state: HashState, mutations: list[Mutation]
) -> None:
    added, removed = _compute_mac_deltas(mutations)
    app_state_store.put_version(name, state)
    if removed:
        app_state_store.delete_mutation_macs(name, removed)
    if added:
        app_state_store.put_mutation_macs(name, state.version, added)


# --- live syncer -----------------------------------------------------


class _Transport(Protocol):
    async def send(self, plaintext: bytes) -> None: ...


class _IqMap(Protocol):
    def register(self, iq_id: str) -> Awaitable[Node]: ...

    def cancel(self, iq_id: str) -> None: ...


MutationSink = Callable[[str, list[Mutation]], Awaitable[None]]


class AppStateSyncer:
    """Fetches and applies app-state collections against the live socket.

    Reacts to ``server_sync`` notifications and can be driven directly for
    a specific collection. Decoded mutations are handed to ``on_mutations``
    (the #35d event surface); #35c only fetches, decodes, and persists.
    """

    def __init__(
        self,
        *,
        transport: _Transport,
        iq_map: _IqMap,
        key_store: AppStateKeyStore,
        app_state_store: AppStateStore,
        download_external: DownloadExternal | None = None,
        on_mutations: MutationSink | None = None,
    ) -> None:
        self._transport = transport
        self._iq_map = iq_map
        self._key_store = key_store
        self._app_state_store = app_state_store
        self._download_external = download_external
        self._on_mutations = on_mutations

    async def handle_server_sync(self, node: Node) -> None:
        """Fetch every collection advertised in a ``server_sync`` notification.

        whatsmeow ``handleAppStateNotification``: one incremental fetch per
        ``<collection name= version=>`` child, from the locally stored
        version (not the advertised one — the fetch walks forward itself).
        """
        for collection in node.get_children("collection"):
            name = collection.get_str("name")
            if not name:
                continue
            try:
                await self.fetch(name)
            except Exception:  # noqa: BLE001
                _log.exception("app-state: failed to sync collection %s after server_sync", name)

    async def fetch(
        self, name: str, *, full_sync: bool = False, only_if_not_synced: bool = False
    ) -> list[Mutation]:
        """Sync one collection from the stored cursor to the server's latest.

        Mirrors whatsmeow ``fetchAppState``: a never-synced collection
        (version 0) forces a full snapshot sync; the loop follows
        ``has_more_patches`` until the server has nothing left.
        """
        if full_sync:
            self._app_state_store.delete_version(name)
        state = self._app_state_store.get_version(name)
        if state.version == 0:
            full_sync = True
        elif only_if_not_synced:
            return []

        want_snapshot = full_sync
        has_more = True
        all_mutations: list[Mutation] = []
        while has_more:
            collection = await self._fetch_collection(name, state.version, want_snapshot)
            patch_list = await parse_patch_list(collection, self._download_external)
            want_snapshot = False
            has_more = patch_list.has_more_patches
            mutations, state = apply_patch_list(
                patch_list, self._key_store, self._app_state_store, state
            )
            all_mutations.extend(mutations)

        if all_mutations and self._on_mutations is not None:
            await self._on_mutations(name, all_mutations)
        _log.debug(
            "app-state: synced %s to v%d (%d mutations)", name, state.version, len(all_mutations)
        )
        return all_mutations

    async def _fetch_collection(self, name: str, version: int, want_snapshot: bool) -> Node:
        iq_id = new_message_id()
        node = Node(
            tag="iq",
            attrs={"id": iq_id, "type": "set", "xmlns": _XMLNS, "to": _SERVER},
            content=[build_fetch_collection_content(name, version, want_snapshot)],
        )
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(node))
            resp = await fut
        finally:
            self._iq_map.cancel(iq_id)
        sync = resp.get_child("sync")
        collection = sync.get_child("collection") if sync is not None else None
        if collection is None:
            raise ValueError(f"app-state fetch for {name} missing <sync><collection>")
        return collection
