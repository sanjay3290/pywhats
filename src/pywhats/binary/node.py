# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Node dataclass for the XMPP-style stanza tree used on the wire.

The wire format framing this represents is an XMPP-shaped tree:
every node has a tag, a dict of attributes, and an optional
``content`` which is either a terminal byte string, a list of child
nodes, or nothing.

Prose references consulted (no reference-implementation source read):
  * WhatsApp web protocol reverse-engineering writeups (various blog
    posts 2015-2023) describing the XMPP-over-binary stanza shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pywhats.events import JID

AttrValue = str | int | JID
NodeContent = bytes | list["Node"] | None


@dataclass
class Node:
    """A single XMPP-style stanza."""

    tag: str
    attrs: dict[str, AttrValue] = field(default_factory=dict)
    content: NodeContent = None

    def get_attr(self, name: str, default: AttrValue | None = None) -> AttrValue | None:
        return self.attrs.get(name, default)

    def get_str(self, name: str, default: str = "") -> str:
        v = self.attrs.get(name)
        if v is None:
            return default
        if isinstance(v, JID):
            return str(v)
        return str(v)

    def get_children(self, tag: str | None = None) -> list[Node]:
        if not isinstance(self.content, list):
            return []
        if tag is None:
            return list(self.content)
        return [c for c in self.content if c.tag == tag]

    def get_child(self, tag: str) -> Node | None:
        for c in self.get_children(tag):
            return c
        return None

    def content_bytes(self) -> bytes:
        if isinstance(self.content, (bytes, bytearray)):
            return bytes(self.content)
        return b""
