# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Per-peer long-term Signal identity public key cache.

The Double Ratchet itself doesn't carry the peer's long-term identity
public key — but the WhatsApp wire format needs it for two things:

  1. Computing the X3DH-shaped associated data
     ``IK_initiator_pub || IK_responder_pub`` that gets fed to every
     ratchet encrypt/decrypt.
  2. The HMAC inputs on the libsignal v3.3 SignalMessage trailer
     (``HMAC(mac_key, sender_id_33b || receiver_id_33b || ...)``).

The Sender learns the peer's identity from the prekey-bundle iq; the
Receiver learns it from the inner pkmsg's ``identityKey`` field. In
both cases the value is stable for the peer's account, so we cache it
and reuse it on every subsequent message.

``InMemoryIdentityStore`` is the volatile implementation; persistent
callers use
:class:`~pywhats.signal.experimental.sqlite_store.SqliteIdentityStore`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class IdentityStore(Protocol):
    def load(self, session_id: str) -> bytes | None: ...

    def save(self, session_id: str, identity_public: bytes) -> None: ...

    def delete(self, session_id: str) -> None: ...


class InMemoryIdentityStore:
    """Volatile dict — useful for tests and ephemeral runs."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def load(self, session_id: str) -> bytes | None:
        return self._store.get(session_id)

    def save(self, session_id: str, identity_public: bytes) -> None:
        if len(identity_public) != 32:
            raise ValueError(f"identity_public must be 32 bytes, got {len(identity_public)}")
        self._store[session_id] = bytes(identity_public)

    def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)
