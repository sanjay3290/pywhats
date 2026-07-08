# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Tests for the SQLite-backed Signal persistence store."""

from __future__ import annotations

import os
import stat
import warnings
from pathlib import Path

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.signal.experimental import (  # noqa: E402
    IdentityKeyPair,
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
from pywhats.signal.experimental.ratchet import RatchetState  # noqa: E402
from pywhats.signal.experimental.sqlite_store import SqliteStore  # noqa: E402


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


def test_session_store_round_trip(tmp_path: Path) -> None:
    alice, bob, ad = _fresh_session()
    store = SqliteStore(tmp_path / "state.db")
    assert store.sessions.load("peer") is None
    store.sessions.save("peer", alice)
    restored = store.sessions.load("peer")
    assert restored is not None
    h, ct, _mk = ratchet_encrypt(restored, b"hi", ad)
    assert ratchet_decrypt(bob, h, ct, ad) == b"hi"
    store.sessions.delete("peer")
    assert store.sessions.load("peer") is None
    store.close()


def test_session_survives_reopen(tmp_path: Path) -> None:
    alice, bob, ad = _fresh_session()
    db = tmp_path / "state.db"
    store = SqliteStore(db)
    store.sessions.save("peer", alice)
    store.identities.save("peer", b"\x01" * 32)
    store.close()

    # Simulate a process restart: a brand-new connection to the same file.
    reopened = SqliteStore(db)
    restored = reopened.sessions.load("peer")
    assert restored is not None
    assert reopened.identities.load("peer") == b"\x01" * 32
    h, ct, _mk = ratchet_encrypt(restored, b"after restart", ad)
    assert ratchet_decrypt(bob, h, ct, ad) == b"after restart"
    reopened.close()


def test_identity_store_validates_length(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "state.db")
    assert store.identities.load("p") is None
    store.identities.save("p", b"\x02" * 32)
    assert store.identities.load("p") == b"\x02" * 32
    try:
        store.identities.save("p", b"\x02" * 31)
        raise AssertionError("expected ValueError for short identity")
    except ValueError:
        pass
    store.identities.delete("p")
    assert store.identities.load("p") is None
    store.close()


def test_lid_map_bidirectional_and_reassignment(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "state.db")
    lm = store.lid_map
    assert lm.get_lid("pn1") is None
    lm.set("pn1", "lid1")
    assert lm.get_lid("pn1") == "lid1"
    assert lm.get_pn("lid1") == "pn1"

    # Reassigning the PN to a new LID drops the stale reverse mapping.
    lm.set("pn1", "lid2")
    assert lm.get_lid("pn1") == "lid2"
    assert lm.get_pn("lid1") is None
    assert lm.get_pn("lid2") == "pn1"
    store.close()


def test_lid_map_survives_reopen(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    store = SqliteStore(db)
    store.lid_map.set("pn9", "lid9")
    store.close()
    reopened = SqliteStore(db)
    assert reopened.lid_map.get_lid("pn9") == "lid9"
    reopened.close()


def test_prekey_store_round_trip_and_max_id(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    store = SqliteStore(db)
    assert store.prekeys.load(1) is None
    assert store.prekeys.max_id() == 0
    opk1 = generate_pre_key(1)
    opk7 = generate_pre_key(7)
    store.prekeys.save(opk1)
    store.prekeys.save(opk7)
    assert store.prekeys.max_id() == 7
    store.close()

    reopened = SqliteStore(db)
    got = reopened.prekeys.load(7)
    assert got is not None
    assert got.private == opk7.private
    assert got.public == opk7.public
    reopened.prekeys.delete(7)
    assert reopened.prekeys.load(7) is None
    assert reopened.prekeys.max_id() == 1
    reopened.close()


def test_transaction_commits_facet_writes_together(tmp_path: Path) -> None:
    alice, _bob, _ad = _fresh_session()
    db = tmp_path / "state.db"
    store = SqliteStore(db)
    store.prekeys.save(generate_pre_key(9))
    with store.transaction():
        store.sessions.save("peer", alice)
        store.identities.save("peer", b"\x03" * 32)
        store.prekeys.delete(9)
    store.close()

    reopened = SqliteStore(db)
    assert reopened.sessions.load("peer") is not None
    assert reopened.identities.load("peer") == b"\x03" * 32
    assert reopened.prekeys.load(9) is None
    reopened.close()


def test_transaction_rolls_back_all_writes_on_error(tmp_path: Path) -> None:
    alice, _bob, _ad = _fresh_session()
    store = SqliteStore(tmp_path / "state.db")
    store.prekeys.save(generate_pre_key(9))
    try:
        with store.transaction():
            store.prekeys.delete(9)
            store.sessions.save("peer", alice)
            raise RuntimeError("crash between writes")
    except RuntimeError:
        pass
    # Neither write is visible: the OPK survives, the session does not.
    assert store.sessions.load("peer") is None
    assert store.prekeys.load(9) is not None
    store.close()


def test_db_file_is_0600(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    store = SqliteStore(db)
    store.close()
    if os.name == "posix":
        mode = stat.S_IMODE(db.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
