# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Read receipts + presence: stanza builders and inbound parsers (issue #38).

Small, self-contained wire features that make the client behave like a
real linked device — mark messages read (blue ticks), announce
online/typing state, and surface peer receipts/presence as events.

Builders mirror whatsmeow ``receipt.go`` (``MarkRead``) and
``presence.go`` (``SendPresence`` / ``SubscribePresence`` /
``SendChatPresence``); parsers mirror ``handlePresence`` /
``handleChatState`` and the receipt handling in ``receipt.go``. Privacy
tokens (the optional ``<tctoken>`` on a subscribe) are not modelled — the
client has none yet, and whatsmeow subscribes without one when absent.
"""

from __future__ import annotations

from pywhats.binary import Node
from pywhats.binary.jid import parse_jid
from pywhats.binary.node import AttrValue
from pywhats.events import JID, ChatPresence, Presence, Receipt

__all__ = [
    "build_read_receipt",
    "build_presence",
    "build_subscribe_presence",
    "build_chat_presence",
    "parse_receipt",
    "parse_presence",
    "parse_chat_presence",
]


# --- outbound builders ----------------------------------------------


def build_read_receipt(
    chat: JID, message_ids: list[str], *, sender: JID | None = None, timestamp: int
) -> Node:
    """Build a ``<receipt type="read">`` for one or more displayed messages.

    whatsmeow ``MarkRead``: the primary id is the ``id`` attr; any extra
    ids go in ``<list><item id=.../></list>``. In a group the original
    sender is carried as ``participant``.
    """
    if not message_ids:
        raise ValueError("message_ids must not be empty")
    attrs: dict[str, AttrValue] = {
        "id": message_ids[0],
        "type": "read",
        "to": chat,
        "t": str(timestamp),
    }
    if sender is not None:
        attrs["participant"] = sender
    content: list[Node] | None = None
    if len(message_ids) > 1:
        items = [Node(tag="item", attrs={"id": mid}) for mid in message_ids[1:]]
        content = [Node(tag="list", content=items)]
    return Node(tag="receipt", attrs=attrs, content=content)


def build_presence(state: str, *, name: str | None = None) -> Node:
    """Build a global ``<presence type=available|unavailable>`` stanza.

    whatsmeow ``SendPresence`` carries the push name so peers see the
    account's display name rather than "-".
    """
    attrs: dict[str, AttrValue] = {"type": state}
    if name:
        attrs["name"] = name
    return Node(tag="presence", attrs=attrs)


def build_subscribe_presence(jid: JID) -> Node:
    """Build a ``<presence type="subscribe" to=jid>`` stanza (whatsmeow
    ``SubscribePresence``)."""
    return Node(tag="presence", attrs={"type": "subscribe", "to": jid})


def build_chat_presence(own: JID, to: JID, state: str, *, media: str | None = None) -> Node:
    """Build a ``<chatstate>`` typing/recording update (whatsmeow ``SendChatPresence``).

    ``state`` is ``composing`` or ``paused``; ``media="audio"`` on a
    ``composing`` marks recording rather than typing.
    """
    child_attrs: dict[str, AttrValue] = {}
    if state == "composing" and media:
        child_attrs["media"] = media
    return Node(
        tag="chatstate",
        attrs={"from": own, "to": to},
        content=[Node(tag=state, attrs=child_attrs)],
    )


# --- inbound parsers ------------------------------------------------


def parse_receipt(node: Node) -> Receipt:
    """Parse a ``<receipt>`` for our sent messages into a :class:`Receipt`.

    A bare receipt (no ``type``) is a delivery receipt; ``read`` is the
    blue-tick read receipt. Extra message ids are read out of ``<list>``.
    """
    ids = [node.get_str("id")]
    lst = node.get_child("list")
    if lst is not None:
        ids.extend(item.get_str("id") for item in lst.get_children("item"))
    participant_attr = node.attrs.get("participant")
    return Receipt(
        from_jid=_jid(node.attrs.get("from")),
        message_ids=[mid for mid in ids if mid],
        type=node.get_str("type"),
        timestamp=_int(node.get_str("t")),
        participant=_jid(participant_attr) if participant_attr is not None else None,
    )


def parse_presence(node: Node) -> Presence:
    """Parse a top-level ``<presence>`` peer update (whatsmeow ``handlePresence``)."""
    last = node.get_str("last")
    last_seen: int | None = None
    if last and last != "deny":
        last_seen = _int(last)
    return Presence(
        from_jid=_jid(node.attrs.get("from")),
        unavailable=node.get_str("type") == "unavailable",
        last_seen=last_seen,
    )


def parse_chat_presence(node: Node) -> ChatPresence:
    """Parse a ``<chatstate>`` typing/recording update (whatsmeow ``handleChatState``)."""
    children = node.get_children()
    child = children[0] if children else Node(tag="paused")
    return ChatPresence(
        from_jid=_jid(node.attrs.get("from")),
        state=child.tag,
        media=child.get_str("media"),
    )


def _jid(attr: object) -> JID:
    if isinstance(attr, JID):
        return attr
    if isinstance(attr, str) and attr:
        return parse_jid(attr)
    return JID(user="", server="s.whatsapp.net")


def _int(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return 0
