# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Map decoded app-state mutations to typed events (issue #35d).

Once #35c has decoded a ``SyncdPatch`` into :class:`~pywhats.appstate
.patches.Mutation` objects, this turns each one into the user-facing
event the :class:`~pywhats.client.Client` emits — a muted/pinned/archived
chat, a contact name, or the account's own push name.

Mirrors whatsmeow ``dispatchAppState`` (appstate.go): only a SET mutation
whose ``index[0]`` is a recognised key produces an event; the target JID
comes from ``index[1]`` (absent for the push-name setting). REMOVE
operations and unmodelled indexes yield ``None``.
"""

from __future__ import annotations

from pywhats.appstate.patches import Mutation
from pywhats.binary.jid import parse_jid
from pywhats.events import JID, Archive, Contact, Mute, Pin, PushName

__all__ = ["app_state_mutation_to_event"]

_SET = 0

# App-state index keys (whatsmeow appstate/keys.go). Note ``pin_v1`` and
# ``setting_pushName`` — the wire keys, not the human labels.
_INDEX_MUTE = "mute"
_INDEX_PIN = "pin_v1"
_INDEX_ARCHIVE = "archive"
_INDEX_CONTACT = "contact"
_INDEX_SETTING_PUSH_NAME = "setting_pushName"

_EMPTY_JID = JID(user="", server="s.whatsapp.net")


def app_state_mutation_to_event(mutation: Mutation) -> tuple[str, object] | None:
    """Return ``(event_name, payload)`` for a mutation, or ``None``.

    ``event_name`` is one of ``mute`` / ``pin`` / ``archive`` / ``contact``
    / ``pushname``.
    """
    if mutation.operation != _SET or not mutation.index:
        return None
    key = mutation.index[0]
    action = mutation.action
    ts = int(action.timestamp)  # type: ignore[attr-defined]
    jid = _index_jid(mutation.index)

    if key == _INDEX_MUTE:
        act = action.mute_action  # type: ignore[attr-defined]
        return "mute", Mute(
            jid=jid, muted=act.muted, mute_end_timestamp=act.mute_end_timestamp, timestamp=ts
        )
    if key == _INDEX_PIN:
        return "pin", Pin(jid=jid, pinned=action.pin_action.pinned, timestamp=ts)  # type: ignore[attr-defined]
    if key == _INDEX_ARCHIVE:
        act = action.archive_chat_action  # type: ignore[attr-defined]
        return "archive", Archive(jid=jid, archived=act.archived, timestamp=ts)
    if key == _INDEX_CONTACT:
        act = action.contact_action  # type: ignore[attr-defined]
        return "contact", Contact(
            jid=jid, first_name=act.first_name, full_name=act.full_name, timestamp=ts
        )
    if key == _INDEX_SETTING_PUSH_NAME:
        return "pushname", PushName(name=action.push_name_setting.name, timestamp=ts)  # type: ignore[attr-defined]
    return None


def _index_jid(index: list[str]) -> JID:
    if len(index) > 1 and index[1]:
        try:
            return parse_jid(index[1])
        except Exception:  # noqa: BLE001
            return _EMPTY_JID
    return _EMPTY_JID
