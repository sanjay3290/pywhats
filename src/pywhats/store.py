# SPDX-License-Identifier: Apache-2.0
"""Persistent device credential store.

After a successful QR pairing, the device-level identity (Noise static key,
Signal identity key, registration ID, signed prekey, server-assigned JID and
device ID, and the server's signed device-identity blob) must survive process
restarts so that ``connect()`` can resume the session instead of re-pairing.

This module handles only device-level identity. Per-conversation Signal
session state (ratchet chains, skipped message keys, etc.) lives in
``pywhats.signal.experimental.store``.

Format
------
Single JSON file. All binary values are base64-encoded (standard alphabet,
with padding). The top-level object has a ``version`` field (currently ``1``)
for future schema migrations.

Writes are atomic: a temp file in the same directory is written, ``fsync``-ed,
then ``os.replace``-d over the destination. The file is created with mode
``0o600``. Load refuses to read a file whose permissions grant any read or
write bit to group or other — use this as a cheap tripwire for stores that
have leaked readable permissions.

Concurrency policy
------------------
**Single-writer-only.** The store does not take an OS-level lock. Two
processes saving concurrently may each produce a well-formed file (atomic
rename guarantees no torn JSON), but one process's changes will silently
overwrite the other's. Callers that run multiple writers must coordinate
externally (``fcntl.flock``, a pidfile, or similar). Readers are always safe.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from pywhats.errors import PyWhatsError
from pywhats.signal.experimental.keys import IdentityKeyPair, SignedPreKey

SCHEMA_VERSION = 1


class StoreError(PyWhatsError):
    """Base class for device-store errors."""


class StoreSecurityError(StoreError):
    """Raised when on-disk permissions fail the safety check."""


class StoreCorruptError(StoreError):
    """Raised when the store file exists but cannot be parsed."""


class StoreVersionError(StoreError):
    """Raised when the on-disk schema version is not understood."""


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    if not isinstance(s, str):
        raise StoreCorruptError("expected base64 string, got non-string")
    try:
        return base64.b64decode(s, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise StoreCorruptError(f"invalid base64: {exc}") from exc


@dataclass(slots=True)
class JIDTuple:
    """Serializable JID triple. Mirrors ``pywhats.events.JID`` minus helpers."""

    user: str
    server: str
    device: int


@dataclass(slots=True)
class DeviceStore:
    """Device-level identity persisted between runs.

    All ``bytes`` fields hold raw key material and are never included in
    ``repr()`` output.
    """

    # Noise static keypair (X25519), used for the WA Noise_XX handshake.
    noise_private: bytes
    noise_public: bytes

    # Long-term Signal identity keypair (X25519, used with XEdDSA).
    identity_private: bytes
    identity_public: bytes

    # Server-assigned registration ID (uint32, 0 .. 2**32 - 1).
    registration_id: int

    # Current signed prekey.
    signed_pre_key_id: int
    signed_pre_key_private: bytes
    signed_pre_key_public: bytes
    signed_pre_key_signature: bytes

    # Our full JID as issued by the server after pairing.
    jid: JIDTuple | None = None

    # Server-assigned device ID (may duplicate ``jid.device`` but the server
    # sometimes reports it separately during pairing).
    device_id: int | None = None

    # The server's ADVSignedDeviceIdentity protobuf blob, echoed back on
    # resume so the server accepts us as an already-paired device.
    adv_signed_device_identity: bytes | None = None

    # The user's WhatsApp display name (push name), captured during
    # pair-success and reused as the ``name`` attribute on outbound
    # ``<presence>`` stanzas.
    push_name: str | None = None

    # Server-issued LID (Linked-Device IDentity). Stashed from the
    # ``<success>`` stanza after login; not yet used on the wire but
    # retained so the daemon can mint LID-keyed JIDs without a refetch.
    lid: str | None = None

    created_at: float = field(default_factory=lambda: time.time())
    pywhats_version: str = ""
    schema_version: int = SCHEMA_VERSION

    # --- repr ---------------------------------------------------------

    # Fields that contain secret key material. Never let these surface in
    # __repr__ output or logs.
    _SECRET_FIELDS = frozenset(
        {
            "noise_private",
            "noise_public",
            "identity_private",
            "identity_public",
            "signed_pre_key_private",
            "signed_pre_key_public",
            "signed_pre_key_signature",
            "adv_signed_device_identity",
        }
    )

    def __repr__(self) -> str:
        parts: list[str] = []
        for f in fields(self):
            if f.name.startswith("_"):
                continue
            if f.name in self._SECRET_FIELDS:
                parts.append(f"{f.name}=<redacted>")
            else:
                parts.append(f"{f.name}={getattr(self, f.name)!r}")
        return f"DeviceStore({', '.join(parts)})"

    # --- serialization ------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """Return the dict form that gets written to disk."""
        return {
            "version": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "pywhats_version": self.pywhats_version,
            "created_at": self.created_at,
            "noise_private": _b64e(self.noise_private),
            "noise_public": _b64e(self.noise_public),
            "identity_private": _b64e(self.identity_private),
            "identity_public": _b64e(self.identity_public),
            "registration_id": self.registration_id,
            "signed_pre_key": {
                "id": self.signed_pre_key_id,
                "private": _b64e(self.signed_pre_key_private),
                "public": _b64e(self.signed_pre_key_public),
                "signature": _b64e(self.signed_pre_key_signature),
            },
            "jid": (
                None
                if self.jid is None
                else {
                    "user": self.jid.user,
                    "server": self.jid.server,
                    "device": self.jid.device,
                }
            ),
            "device_id": self.device_id,
            "adv_signed_device_identity": (
                None
                if self.adv_signed_device_identity is None
                else _b64e(self.adv_signed_device_identity)
            ),
            "push_name": self.push_name,
            "lid": self.lid,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DeviceStore:
        if not isinstance(data, dict):
            raise StoreCorruptError("store root must be a JSON object")
        ver = data.get("version")
        if ver is None:
            raise StoreCorruptError("missing 'version' field")
        if ver != SCHEMA_VERSION:
            raise StoreVersionError(f"unsupported store version {ver}, expected {SCHEMA_VERSION}")

        try:
            spk = data["signed_pre_key"]
            if not isinstance(spk, dict):
                raise StoreCorruptError("signed_pre_key must be an object")
            jid_raw = data.get("jid")
            jid: JIDTuple | None
            if jid_raw is None:
                jid = None
            elif isinstance(jid_raw, dict):
                jid = JIDTuple(
                    user=str(jid_raw["user"]),
                    server=str(jid_raw["server"]),
                    device=int(jid_raw["device"]),
                )
            else:
                raise StoreCorruptError("jid must be an object or null")

            adv = data.get("adv_signed_device_identity")
            adv_bytes = None if adv is None else _b64d(adv)

            reg_id = data["registration_id"]
            if not isinstance(reg_id, int) or reg_id < 0 or reg_id > 0xFFFFFFFF:
                raise StoreCorruptError("registration_id out of range for uint32")

            return cls(
                noise_private=_b64d(data["noise_private"]),
                noise_public=_b64d(data["noise_public"]),
                identity_private=_b64d(data["identity_private"]),
                identity_public=_b64d(data["identity_public"]),
                registration_id=reg_id,
                signed_pre_key_id=int(spk["id"]),
                signed_pre_key_private=_b64d(spk["private"]),
                signed_pre_key_public=_b64d(spk["public"]),
                signed_pre_key_signature=_b64d(spk["signature"]),
                jid=jid,
                device_id=(None if data.get("device_id") is None else int(data["device_id"])),
                adv_signed_device_identity=adv_bytes,
                push_name=(None if data.get("push_name") is None else str(data["push_name"])),
                lid=(None if data.get("lid") is None else str(data["lid"])),
                created_at=float(data.get("created_at", time.time())),
                pywhats_version=str(data.get("pywhats_version", "")),
                schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
            )
        except KeyError as exc:
            raise StoreCorruptError(f"missing required field: {exc.args[0]}") from exc
        except (TypeError, ValueError) as exc:
            raise StoreCorruptError(f"malformed field: {exc}") from exc

    # --- convenience constructors ------------------------------------

    @classmethod
    def new(
        cls,
        identity: IdentityKeyPair,
        signed_pre_key: SignedPreKey,
        noise_private: bytes,
        noise_public: bytes,
        registration_id: int,
        *,
        pywhats_version: str = "",
    ) -> DeviceStore:
        """Build an un-paired store from freshly-generated material."""
        return cls(
            noise_private=noise_private,
            noise_public=noise_public,
            identity_private=identity.private,
            identity_public=identity.public,
            registration_id=registration_id,
            signed_pre_key_id=signed_pre_key.key_id,
            signed_pre_key_private=signed_pre_key.private,
            signed_pre_key_public=signed_pre_key.public,
            signed_pre_key_signature=signed_pre_key.signature,
            pywhats_version=pywhats_version,
        )

    def identity_key_pair(self) -> IdentityKeyPair:
        return IdentityKeyPair(private=self.identity_private, public=self.identity_public)

    def signed_pre_key(self) -> SignedPreKey:
        return SignedPreKey(
            key_id=self.signed_pre_key_id,
            private=self.signed_pre_key_private,
            public=self.signed_pre_key_public,
            signature=self.signed_pre_key_signature,
        )

    # --- disk IO -----------------------------------------------------

    def save(self, path: str | os.PathLike[str]) -> None:
        """Atomically write the store to ``path`` with mode 0600."""
        save_device_store(self, path)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> DeviceStore:
        return load_device_store(path)


# -------------------- module-level IO helpers --------------------


_UNSAFE_MODE_BITS = (
    stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
)


def _check_permissions(path: Path) -> None:
    """Refuse to load a store file with any group/other bits set.

    Windows has no meaningful POSIX mode — ``st_mode`` still exposes the
    bits but they aren't enforced. We only enforce the check on POSIX.
    """
    if os.name != "posix":
        return
    try:
        st_mode = path.stat().st_mode
    except FileNotFoundError:
        # Let the caller's read() surface the real FileNotFoundError.
        return
    except OSError as exc:  # pragma: no cover - stat errors are rare
        raise StoreError(f"cannot stat store file: {exc}") from exc
    if st_mode & _UNSAFE_MODE_BITS:
        raise StoreSecurityError(
            f"refusing to load {path}: file permissions "
            f"{stat.filemode(st_mode)} expose credentials to group/other; "
            "chmod 600 the file before continuing"
        )


def save_device_store(store: DeviceStore, path: str | os.PathLike[str]) -> None:
    """Atomically write ``store`` to ``path``.

    Creates parent directories as needed. The final file has mode ``0o600``.
    """
    dest = Path(path).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(store.to_json(), indent=2, sort_keys=True).encode("utf-8")

    # Write to a temp file in the same directory so os.replace is atomic.
    fd, tmp_path = tempfile.mkstemp(prefix=".devstore-", suffix=".tmp", dir=str(dest.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, dest)
    except Exception:
        # Best-effort cleanup; ignore errors if the temp file is gone.
        try:
            os.unlink(tmp_path)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                pass
        raise

    # Directory fsync so the rename is durable. Not fatal if it fails
    # (some filesystems like tmpfs don't support it).
    try:
        dir_fd = os.open(str(dest.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def load_device_store(path: str | os.PathLike[str]) -> DeviceStore:
    """Load a device store, refusing files with unsafe permissions."""
    p = Path(path).expanduser()
    _check_permissions(p)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StoreError(f"cannot read store file: {exc}") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreCorruptError(f"store file is not valid JSON: {exc}") from exc

    return DeviceStore.from_json(data)


# Re-export as a small public surface. Use ``asdict`` in tests only.
__all__ = [
    "SCHEMA_VERSION",
    "DeviceStore",
    "JIDTuple",
    "StoreCorruptError",
    "StoreError",
    "StoreSecurityError",
    "StoreVersionError",
    "load_device_store",
    "save_device_store",
]


# Touch ``asdict`` so mypy doesn't complain about the unused import if we
# ever remove it. It's kept as a convenience for downstream tooling.
_ = asdict
