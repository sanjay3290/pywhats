# SPDX-License-Identifier: Apache-2.0
"""Tests for the persistent device credential store."""

from __future__ import annotations

import json
import os
import stat
import warnings
from pathlib import Path

import pytest

# Silence the experimental-Signal DeprecationWarning at import time so the
# rest of this module can import cleanly.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from pywhats.signal.experimental.keys import IdentityKeyPair, SignedPreKey

from pywhats.client import Client
from pywhats.store import (
    SCHEMA_VERSION,
    DeviceStore,
    JIDTuple,
    StoreCorruptError,
    StoreSecurityError,
    StoreVersionError,
    load_device_store,
    save_device_store,
)


def _make_store() -> DeviceStore:
    identity = IdentityKeyPair.generate()
    spk = SignedPreKey.generate(identity, key_id=7)
    # Noise static: independent X25519 pair; use another IdentityKeyPair as a
    # convenient source of 32-byte X25519 material.
    noise = IdentityKeyPair.generate()
    store = DeviceStore.new(
        identity=identity,
        signed_pre_key=spk,
        noise_private=noise.private,
        noise_public=noise.public,
        registration_id=0xDEADBEEF,
        pywhats_version="0.0.1-test",
    )
    store.jid = JIDTuple(user="15551234567", server="s.whatsapp.net", device=3)
    store.device_id = 3
    store.adv_signed_device_identity = b"\x01\x02\x03 protobuf blob \xfe\xff"
    return store


# ----------------------------- round-trip -----------------------------


def test_round_trip_all_fields(tmp_path: Path) -> None:
    original = _make_store()
    path = tmp_path / "dev.json"

    save_device_store(original, path)
    loaded = load_device_store(path)

    assert loaded.noise_private == original.noise_private
    assert loaded.noise_public == original.noise_public
    assert loaded.identity_private == original.identity_private
    assert loaded.identity_public == original.identity_public
    assert loaded.registration_id == original.registration_id
    assert loaded.signed_pre_key_id == original.signed_pre_key_id
    assert loaded.signed_pre_key_private == original.signed_pre_key_private
    assert loaded.signed_pre_key_public == original.signed_pre_key_public
    assert loaded.signed_pre_key_signature == original.signed_pre_key_signature
    assert loaded.jid == original.jid
    assert loaded.device_id == original.device_id
    assert loaded.adv_signed_device_identity == original.adv_signed_device_identity
    assert loaded.pywhats_version == original.pywhats_version
    assert loaded.created_at == pytest.approx(original.created_at)
    assert loaded.schema_version == SCHEMA_VERSION


def test_round_trip_minimal_unpaired(tmp_path: Path) -> None:
    """A newly-minted, un-paired store (no JID yet) still round-trips."""
    store = _make_store()
    store.jid = None
    store.device_id = None
    store.adv_signed_device_identity = None

    path = tmp_path / "dev.json"
    save_device_store(store, path)
    loaded = load_device_store(path)

    assert loaded.jid is None
    assert loaded.device_id is None
    assert loaded.adv_signed_device_identity is None
    assert loaded.identity_key_pair().public == store.identity_public
    assert loaded.signed_pre_key().verify(store.identity_public)


# ----------------------------- file mode ------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only permission semantics")
def test_saved_file_mode_is_0600(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only permission semantics")
def test_load_rejects_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    os.chmod(path, 0o644)  # group + other get read bit
    with pytest.raises(StoreSecurityError, match="group/other"):
        load_device_store(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only permission semantics")
def test_load_rejects_group_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    os.chmod(path, 0o640)
    with pytest.raises(StoreSecurityError):
        load_device_store(path)


# ----------------------------- errors ---------------------------------


def test_corrupt_json_raises_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    path.write_bytes(b"{not valid json")
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError, match="not valid JSON"):
        load_device_store(path)


def test_empty_file_raises_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    path.write_bytes(b"")
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError):
        load_device_store(path)


def test_schema_version_mismatch_raises(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    data = json.loads(path.read_text())
    data["version"] = 999
    path.write_text(json.dumps(data))
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreVersionError, match="unsupported store version 999, expected 1"):
        load_device_store(path)


def test_missing_version_raises_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    data = json.loads(path.read_text())
    del data["version"]
    path.write_text(json.dumps(data))
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError, match="version"):
        load_device_store(path)


def test_missing_required_field_raises_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    data = json.loads(path.read_text())
    del data["noise_private"]
    path.write_text(json.dumps(data))
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError, match="missing required field"):
        load_device_store(path)


def test_registration_id_out_of_range_raises(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    data = json.loads(path.read_text())
    data["registration_id"] = 2**33
    path.write_text(json.dumps(data))
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError, match="uint32"):
        load_device_store(path)


def test_bad_base64_raises_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)
    data = json.loads(path.read_text())
    data["identity_private"] = "!!! not base64 !!!"
    path.write_text(json.dumps(data))
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError):
        load_device_store(path)


# ----------------------------- repr safety ----------------------------


def test_repr_hides_key_material() -> None:
    store = _make_store()
    r = repr(store)
    # No raw key bytes should appear in the repr.
    for secret in (
        store.noise_private,
        store.identity_private,
        store.signed_pre_key_private,
    ):
        # bytes() repr would be "b'...'" — ensure that exact sequence isn't present.
        assert repr(secret) not in r
    # And "<redacted>" should appear for secret fields.
    assert "<redacted>" in r
    assert "noise_private=<redacted>" in r
    assert "identity_private=<redacted>" in r
    # Non-secret fields are fine to surface.
    assert "registration_id=" in r


# ----------------------------- atomic writes --------------------------


def test_save_is_atomic_when_destination_exists(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    first = _make_store()
    save_device_store(first, path)
    size_before = path.stat().st_size

    second = _make_store()
    second.registration_id = 1
    save_device_store(second, path)

    # Should still be valid JSON after overwrite (no torn write).
    loaded = load_device_store(path)
    assert loaded.registration_id == 1
    assert path.stat().st_size > 0
    # Temp files should be cleaned up.
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(".devstore-")]
    assert stray == [], f"left behind temp files: {stray}"
    assert size_before > 0  # sanity


def test_save_creates_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "dev.json"
    save_device_store(_make_store(), path)
    assert path.exists()


# ----------------------------- Client wiring --------------------------


def test_client_loads_existing_session(tmp_path: Path) -> None:
    path = tmp_path / "dev.json"
    save_device_store(_make_store(), path)

    client = Client(session_path=str(path))
    assert client.device is not None
    assert client.device.registration_id == 0xDEADBEEF


def test_client_missing_session_file_is_ok(tmp_path: Path) -> None:
    """If the session file doesn't exist yet, Client starts un-paired."""
    path = tmp_path / "does-not-exist.json"
    client = Client(session_path=str(path))
    assert client.device is None


def test_client_propagates_corrupt_store(tmp_path: Path) -> None:
    """A corrupt store must not be silently reset — the user has to intervene."""
    path = tmp_path / "dev.json"
    path.write_bytes(b"garbage")
    if os.name == "posix":
        os.chmod(path, 0o600)
    with pytest.raises(StoreCorruptError):
        Client(session_path=str(path))


def test_client_with_no_session_path() -> None:
    client = Client()
    assert client.device is None
