# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Messaging address helpers shared by sender and receiver."""

from __future__ import annotations

from pywhats.events import JID
from pywhats.signal.experimental import IdentityStore, SessionStore


def session_id(jid: JID) -> str:
    """Stable Signal session key for a specific device address."""
    return f"{jid.user}:{jid.device}@{jid.server}"


def migrate_pn_session_to_lid(
    *,
    sessions: SessionStore,
    identity_store: IdentityStore,
    pn: JID,
    lid: JID,
) -> bool:
    """Move an existing PN-keyed Signal session to its LID device key."""
    pn_key = session_id(pn)
    lid_key = session_id(lid)
    state = sessions.load(pn_key)
    if state is None or sessions.load(lid_key) is not None:
        return False
    sessions.save(lid_key, state)
    peer_identity = identity_store.load(pn_key)
    if peer_identity is not None:
        identity_store.save(lid_key, peer_identity)
    sessions.delete(pn_key)
    identity_store.delete(pn_key)
    return True
