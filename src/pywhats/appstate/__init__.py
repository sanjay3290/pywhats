# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""App-state (``w:sync:app:state``) synchronisation — issue #35.

Sub-units:

* 35a — sync-key storage (:mod:`pywhats.appstate.keys`).
* 35b — mutation crypto + single-patch decode
  (:mod:`pywhats.appstate.crypto`, :mod:`pywhats.appstate.lthash`,
  :mod:`pywhats.appstate.patches`).
* 35c — fetch/apply loop, version + mutation-MAC persistence, and the
  ``server_sync`` reaction (:mod:`pywhats.appstate.store`,
  :mod:`pywhats.appstate.fetch`).

The event surface (turning decoded mutations into contacts/pushname/
mute-pin-archive events) is 35d.

The live syncer lives in :mod:`pywhats.appstate.fetch`
(:class:`~pywhats.appstate.fetch.AppStateSyncer`) and is imported from
there directly — keeping it out of this package ``__init__`` avoids a
circular import, since ``fetch`` pulls in the messaging layer, which in
turn imports the key/store types re-exported here.
"""

from .keys import AppStateKeyStore, AppStateSyncKey, InMemoryAppStateKeyStore
from .store import AppStateStore, InMemoryAppStateStore, MutationMac

__all__ = [
    "AppStateKeyStore",
    "AppStateSyncKey",
    "InMemoryAppStateKeyStore",
    "AppStateStore",
    "InMemoryAppStateStore",
    "MutationMac",
]
