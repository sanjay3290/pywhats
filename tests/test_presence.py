# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Read-receipt + presence stanza construction and inbound parsing (issue #38).

Mirrors whatsmeow ``receipt.go`` (MarkRead) and ``presence.go``
(SendPresence / SubscribePresence / SendChatPresence / handlePresence /
handleChatState).
"""

from __future__ import annotations

from pywhats.binary import Node
from pywhats.events import JID, ChatPresence, Presence, Receipt
from pywhats.messaging.presence import (
    build_chat_presence,
    build_presence,
    build_read_receipt,
    build_subscribe_presence,
    parse_chat_presence,
    parse_presence,
    parse_receipt,
)

_CHAT = JID(user="123", server="s.whatsapp.net")


# --- outbound builders ----------------------------------------------


def test_read_receipt_single_id() -> None:
    node = build_read_receipt(_CHAT, ["ABC"], timestamp=1700)
    assert node.tag == "receipt"
    assert node.get_str("type") == "read"
    assert node.get_str("id") == "ABC"
    assert node.attrs["to"] == _CHAT
    assert node.get_str("t") == "1700"
    assert node.get_children() == []


def test_read_receipt_multiple_ids_uses_list() -> None:
    node = build_read_receipt(_CHAT, ["A", "B", "C"], timestamp=1)
    assert node.get_str("id") == "A"
    lst = node.get_child("list")
    assert lst is not None
    items = lst.get_children("item")
    assert [i.get_str("id") for i in items] == ["B", "C"]


def test_read_receipt_group_sets_participant() -> None:
    group = JID(user="9990", server="g.us")
    sender = JID(user="456", server="s.whatsapp.net")
    node = build_read_receipt(group, ["X"], sender=sender, timestamp=1)
    assert node.attrs["participant"] == sender


def test_presence_available_carries_name() -> None:
    node = build_presence("available", name="Alice")
    assert node.tag == "presence"
    assert node.get_str("type") == "available"
    assert node.get_str("name") == "Alice"


def test_subscribe_presence() -> None:
    node = build_subscribe_presence(_CHAT)
    assert node.tag == "presence"
    assert node.get_str("type") == "subscribe"
    assert node.attrs["to"] == _CHAT


def test_chat_presence_composing() -> None:
    own = JID(user="me", server="s.whatsapp.net")
    node = build_chat_presence(own, _CHAT, "composing")
    assert node.tag == "chatstate"
    assert node.attrs["from"] == own
    assert node.attrs["to"] == _CHAT
    child = node.get_children()[0]
    assert child.tag == "composing"


def test_chat_presence_recording_sets_media() -> None:
    own = JID(user="me", server="s.whatsapp.net")
    node = build_chat_presence(own, _CHAT, "composing", media="audio")
    child = node.get_children()[0]
    assert child.tag == "composing"
    assert child.get_str("media") == "audio"


# --- inbound parsers ------------------------------------------------


def test_parse_read_receipt() -> None:
    node = Node(
        tag="receipt",
        attrs={"from": "123@s.whatsapp.net", "type": "read", "id": "M1", "t": "1700"},
    )
    evt = parse_receipt(node)
    assert isinstance(evt, Receipt)
    assert evt.type == "read"
    assert evt.message_ids == ["M1"]
    assert evt.from_jid.user == "123"
    assert evt.timestamp == 1700


def test_parse_delivery_receipt_defaults_type_empty_and_reads_list() -> None:
    node = Node(
        tag="receipt",
        attrs={"from": "123@s.whatsapp.net", "id": "M1", "t": "5"},
        content=[Node(tag="list", content=[Node(tag="item", attrs={"id": "M2"})])],
    )
    evt = parse_receipt(node)
    assert evt.type == ""  # bare receipt == delivery
    assert evt.message_ids == ["M1", "M2"]


def test_parse_presence_unavailable_with_last_seen() -> None:
    node = Node(
        tag="presence",
        attrs={"from": "123@s.whatsapp.net", "type": "unavailable", "last": "1699"},
    )
    evt = parse_presence(node)
    assert isinstance(evt, Presence)
    assert evt.unavailable is True
    assert evt.last_seen == 1699


def test_parse_presence_available_deny_last() -> None:
    node = Node(tag="presence", attrs={"from": "123@s.whatsapp.net", "last": "deny"})
    evt = parse_presence(node)
    assert evt.unavailable is False
    assert evt.last_seen is None


def test_parse_chat_presence_composing() -> None:
    node = Node(
        tag="chatstate",
        attrs={"from": "123@s.whatsapp.net"},
        content=[Node(tag="composing")],
    )
    evt = parse_chat_presence(node)
    assert isinstance(evt, ChatPresence)
    assert evt.state == "composing"
    assert evt.from_jid.user == "123"
