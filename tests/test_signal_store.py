# SPDX-License-Identifier: Apache-2.0
"""Tests for the session stores."""

from __future__ import annotations

import warnings

import pytest

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.signal.experimental import (  # noqa: E402
    IdentityKeyPair,
    InMemorySessionStore,
    PreKeyBundle,
    SignedPreKey,
    generate_pre_key,
    ratchet_decrypt,
    ratchet_encrypt,
    ratchet_init_alice,
    ratchet_init_bob,
    x3dh_initiator,
    x3dh_responder,
)
from pywhats.signal.experimental.keys import SignalCryptoError  # noqa: E402
from pywhats.signal.experimental.ratchet import RatchetState  # noqa: E402
from pywhats.signal.experimental.store import (  # noqa: E402
    deserialize_state,
    serialize_state,
)


def _fresh_session() -> tuple[RatchetState, RatchetState, bytes]:
    bob_ik = IdentityKeyPair.generate()
    bob_spk = SignedPreKey.generate(bob_ik, key_id=1)
    bob_opk = generate_pre_key(key_id=42)
    bundle = PreKeyBundle(
        identity_key=bob_ik.public,
        signed_pre_key_id=bob_spk.key_id,
        signed_pre_key_public=bob_spk.public,
        signed_pre_key_signature=bob_spk.signature,
        one_time_pre_key_id=bob_opk.key_id,
        one_time_pre_key_public=bob_opk.public,
    )
    alice_ik = IdentityKeyPair.generate()
    ar = x3dh_initiator(alice_ik, bundle)
    br = x3dh_responder(bob_ik, bob_spk, bob_opk, ar.identity_public, ar.ephemeral_public)
    alice = ratchet_init_alice(ar.shared_secret, bob_spk.public)
    bob = ratchet_init_bob(br.shared_secret, bob_spk.private, bob_spk.public)
    return alice, bob, ar.associated_data


def test_serialize_round_trip() -> None:
    alice, _bob, _ad = _fresh_session()
    data = serialize_state(alice)
    assert data["schema"] == 1
    restored = deserialize_state(data)
    assert restored.dhs_priv == alice.dhs_priv
    assert restored.dhs_pub == alice.dhs_pub
    assert restored.rk == alice.rk
    assert restored.cks == alice.cks
    assert restored.ns == alice.ns


def test_inmemory_store() -> None:
    alice, bob, ad = _fresh_session()
    store = InMemorySessionStore()
    assert store.load("alice") is None
    store.save("alice", alice)
    restored = store.load("alice")
    assert restored is not None
    # Use the restored state to encrypt; bob must be able to decrypt.
    h, ct, _mk = ratchet_encrypt(restored, b"via store", ad)
    pt = ratchet_decrypt(bob, h, ct, ad)
    assert pt == b"via store"

    store.delete("alice")
    assert store.load("alice") is None


def test_schema_version_mismatch_raises() -> None:
    alice, _bob, _ad = _fresh_session()
    data = serialize_state(alice)
    data["schema"] = 999
    with pytest.raises(SignalCryptoError):
        deserialize_state(data)
