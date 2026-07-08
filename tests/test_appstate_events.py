# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Map decoded app-state mutations to typed events (issue #35d).

Mirrors whatsmeow ``dispatchAppState`` (appstate.go): a SET mutation
whose index[0] is a known key becomes a typed event carrying the target
JID (from index[1]) and the action fields. REMOVE mutations and unknown
indexes produce nothing.
"""

from __future__ import annotations

from pywhats.appstate.events import app_state_mutation_to_event
from pywhats.appstate.patches import Mutation
from pywhats.events import JID, Archive, Contact, Mute, Pin, PushName
from pywhats.proto import SyncActionValue

_SET = 0
_REMOVE = 1


def _mutation(index: list[str], action: SyncActionValue, *, operation: int = _SET) -> Mutation:
    return Mutation(
        operation=operation,
        index=index,
        action=action,
        index_mac=b"\x00" * 32,
        value_mac=b"\x00" * 32,
        key_id=b"\x00\x00\x01",
        version=1,
    )


def test_mute_mutation_maps_to_mute_event() -> None:
    action = SyncActionValue(timestamp=111)
    action.mute_action.muted = True
    action.mute_action.mute_end_timestamp = 999
    mapped = app_state_mutation_to_event(_mutation(["mute", "123@s.whatsapp.net"], action))
    assert mapped is not None
    name, event = mapped
    assert name == "mute"
    assert isinstance(event, Mute)
    assert event.jid == JID(user="123", server="s.whatsapp.net")
    assert event.muted is True
    assert event.mute_end_timestamp == 999
    assert event.timestamp == 111


def test_pin_mutation_maps_to_pin_event() -> None:
    action = SyncActionValue(timestamp=5)
    action.pin_action.pinned = True
    mapped = app_state_mutation_to_event(_mutation(["pin_v1", "42@s.whatsapp.net"], action))
    assert mapped is not None
    name, event = mapped
    assert name == "pin"
    assert isinstance(event, Pin)
    assert event.pinned is True
    assert event.jid.user == "42"


def test_archive_mutation_maps_to_archive_event() -> None:
    action = SyncActionValue(timestamp=7)
    action.archive_chat_action.archived = True
    mapped = app_state_mutation_to_event(_mutation(["archive", "7@s.whatsapp.net"], action))
    assert mapped is not None
    name, event = mapped
    assert name == "archive"
    assert isinstance(event, Archive)
    assert event.archived is True


def test_contact_mutation_maps_to_contact_event() -> None:
    action = SyncActionValue(timestamp=3)
    action.contact_action.full_name = "Alice Smith"
    action.contact_action.first_name = "Alice"
    mapped = app_state_mutation_to_event(_mutation(["contact", "1@s.whatsapp.net"], action))
    assert mapped is not None
    name, event = mapped
    assert name == "contact"
    assert isinstance(event, Contact)
    assert event.full_name == "Alice Smith"
    assert event.first_name == "Alice"
    assert event.jid.user == "1"


def test_pushname_mutation_maps_to_pushname_event() -> None:
    action = SyncActionValue(timestamp=9)
    action.push_name_setting.name = "Bob"
    mapped = app_state_mutation_to_event(_mutation(["setting_pushName"], action))
    assert mapped is not None
    name, event = mapped
    assert name == "pushname"
    assert isinstance(event, PushName)
    assert event.name == "Bob"


def test_remove_mutation_maps_to_nothing() -> None:
    action = SyncActionValue(timestamp=1)
    mapped = app_state_mutation_to_event(
        _mutation(["mute", "1@s.whatsapp.net"], action, operation=_REMOVE)
    )
    assert mapped is None


def test_unknown_index_maps_to_nothing() -> None:
    action = SyncActionValue(timestamp=1)
    mapped = app_state_mutation_to_event(_mutation(["star", "1@s", "mid", "1", "0"], action))
    assert mapped is None
