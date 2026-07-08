# SPDX-License-Identifier: Apache-2.0
"""Session storage for the experimental Double Ratchet.

``InMemorySessionStore`` is the volatile implementation (tests, clients
without a ``session_path``); the persistent implementation is
:class:`~pywhats.signal.experimental.sqlite_store.SqliteSessionStore`,
which reuses this module's ``serialize_state``/``deserialize_state``.

Schema is versioned via the ``schema`` top-level field so future format
changes can be detected.

WARNING: These stores persist ratchet keys. Disk encryption is the
caller's responsibility. See ``SECURITY.md``.
"""

from __future__ import annotations

import base64
import json
import warnings
from typing import Protocol, runtime_checkable

from pywhats.signal.experimental.keys import SignalCryptoError
from pywhats.signal.experimental.ratchet import DEFAULT_MAX_SKIP, RatchetState

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)

_SCHEMA_VERSION = 1


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SignalCryptoError("invalid stored session encoding") from exc


def serialize_state(state: RatchetState) -> dict[str, object]:
    return {
        "schema": _SCHEMA_VERSION,
        "dhs_priv": _b64(state.dhs_priv),
        "dhs_pub": _b64(state.dhs_pub),
        "dhr": _b64(state.dhr) if state.dhr is not None else None,
        "rk": _b64(state.rk),
        "cks": _b64(state.cks) if state.cks is not None else None,
        "ckr": _b64(state.ckr) if state.ckr is not None else None,
        "ns": state.ns,
        "nr": state.nr,
        "pn": state.pn,
        "max_skip": state.max_skip,
        "mkskipped": [
            {"dh": _b64(k[0]), "n": k[1], "mk": _b64(v)} for k, v in state.mkskipped.items()
        ],
    }


def deserialize_state(data: dict[str, object]) -> RatchetState:
    schema = data.get("schema")
    if schema != _SCHEMA_VERSION:
        raise SignalCryptoError("unsupported session schema version")
    try:
        dhs_priv = _unb64(str(data["dhs_priv"]))
        dhs_pub = _unb64(str(data["dhs_pub"]))
        rk = _unb64(str(data["rk"]))
        dhr_raw = data.get("dhr")
        dhr = _unb64(str(dhr_raw)) if dhr_raw is not None else None
        cks_raw = data.get("cks")
        cks = _unb64(str(cks_raw)) if cks_raw is not None else None
        ckr_raw = data.get("ckr")
        ckr = _unb64(str(ckr_raw)) if ckr_raw is not None else None
        ns = int(data.get("ns", 0))  # type: ignore[call-overload]
        nr = int(data.get("nr", 0))  # type: ignore[call-overload]
        pn = int(data.get("pn", 0))  # type: ignore[call-overload]
        max_skip = int(data.get("max_skip", DEFAULT_MAX_SKIP))  # type: ignore[call-overload]
        raw_skipped = data.get("mkskipped", []) or []
        if not isinstance(raw_skipped, list):
            raise SignalCryptoError("bad mkskipped field")
        mkskipped: dict[tuple[bytes, int], bytes] = {}
        for entry in raw_skipped:
            if not isinstance(entry, dict):
                raise SignalCryptoError("bad skipped entry")
            mkskipped[(_unb64(str(entry["dh"])), int(entry["n"]))] = _unb64(str(entry["mk"]))
    except KeyError as exc:
        raise SignalCryptoError("missing field in stored session") from exc
    return RatchetState(
        dhs_priv=dhs_priv,
        dhs_pub=dhs_pub,
        dhr=dhr,
        rk=rk,
        cks=cks,
        ckr=ckr,
        ns=ns,
        nr=nr,
        pn=pn,
        mkskipped=mkskipped,
        max_skip=max_skip,
    )


@runtime_checkable
class SessionStore(Protocol):
    def load(self, session_id: str) -> RatchetState | None: ...

    def save(self, session_id: str, state: RatchetState) -> None: ...

    def delete(self, session_id: str) -> None: ...


class InMemorySessionStore:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, object]] = {}

    def load(self, session_id: str) -> RatchetState | None:
        blob = self._store.get(session_id)
        if blob is None:
            return None
        # Deep-ish copy via JSON round-trip to avoid shared mutable refs.
        return deserialize_state(json.loads(json.dumps(blob)))

    def save(self, session_id: str, state: RatchetState) -> None:
        self._store[session_id] = serialize_state(state)

    def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)
