# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Encode :class:`Node` trees to the XMPP-over-binary wire format.

The encoder is intentionally small and pure: it takes a ``Node``
(plus an optional compression flag) and returns a ``bytes`` frame
suitable for handing to the Noise transport layer.

Encoding strategy for a node:

1.  Write a *list header* describing how many "items" follow:
    1 (the tag) + 2 * number-of-attrs + (1 if content else 0).
2.  Write the tag as a tokenised string.
3.  Write each attribute as two items: key, value.
4.  Write the content: either a terminal string / byte string, or a
    nested list of child nodes.

Strings are emitted using the shortest legal form:
single-byte token -> double-byte token -> NIBBLE_8 (digit/sign) ->
HEX_8 (uppercase hex) -> BINARY_8 / BINARY_20 / BINARY_32 length-
prefixed byte strings.

Prose references consulted (no reference-implementation source read):
  * Public XMPP-over-binary reverse-engineering writeups describing
    the list-header + tokenised-string layout.
"""

from __future__ import annotations

import zlib

from pywhats.events import JID

from .node import Node
from .tokens import (
    AD_JID,
    BINARY_8,
    BINARY_20,
    BINARY_32,
    DICTIONARY_0,
    HEX_8,
    HEX_ALPHABET,
    JID_PAIR,
    LIST_8,
    LIST_16,
    LIST_EMPTY,
    NIBBLE_8,
    NIBBLE_ALPHABET,
    lookup_double,
    lookup_single,
)

__all__ = ["encode"]


def encode(node: Node, compress: bool = False) -> bytes:
    """Encode ``node`` into a wire frame.

    ``compress=True`` sets bit 1 (``0x02``) in the flags byte and
    zlib-compresses the stanza payload.
    """
    buf = bytearray()
    _write_node(buf, node)
    payload = bytes(buf)
    flags = 0
    if compress:
        flags |= 0x02
        payload = zlib.compress(payload)
    return bytes([flags]) + payload


# --- Node / list writers --------------------------------------------


def _write_list_header(buf: bytearray, count: int) -> None:
    if count == 0:
        buf.append(LIST_EMPTY)
    elif count < 256:
        buf.append(LIST_8)
        buf.append(count)
    elif count < 1 << 16:
        buf.append(LIST_16)
        buf.extend(count.to_bytes(2, "big"))
    else:
        raise ValueError(f"list too long to encode: {count}")


def _write_node(buf: bytearray, node: Node) -> None:
    has_content = node.content is not None
    count = 1 + 2 * len(node.attrs) + (1 if has_content else 0)
    _write_list_header(buf, count)
    _write_string(buf, node.tag)
    for k, v in node.attrs.items():
        _write_string(buf, k)
        _write_attr_value(buf, v)
    if has_content:
        _write_content(buf, node.content)


def _write_content(buf: bytearray, content: object) -> None:
    if isinstance(content, (bytes, bytearray)):
        _write_bytes(buf, bytes(content))
    elif isinstance(content, str):
        _write_string(buf, content)
    elif isinstance(content, list):
        _write_list_header(buf, len(content))
        for child in content:
            if not isinstance(child, Node):
                raise TypeError(f"child is not Node: {type(child)!r}")
            _write_node(buf, child)
    else:
        raise TypeError(f"unsupported content type: {type(content)!r}")


# --- Attribute values -----------------------------------------------


def _write_attr_value(buf: bytearray, value: object) -> None:
    if isinstance(value, JID):
        _write_jid(buf, value)
    elif isinstance(value, bool):  # must come before int
        _write_string(buf, "true" if value else "false")
    elif isinstance(value, int):
        _write_string(buf, str(value))
    elif isinstance(value, (bytes, bytearray)):
        _write_bytes(buf, bytes(value))
    elif isinstance(value, str):
        _write_string(buf, value)
    else:
        raise TypeError(f"unsupported attr value type: {type(value)!r}")


# --- Strings & byte strings -----------------------------------------


def _write_string(buf: bytearray, s: str) -> None:
    if s == "":
        # Empty string -> empty byte string via BINARY_8 len=0.
        buf.append(BINARY_8)
        buf.append(0)
        return

    single = lookup_single(s)
    if single is not None:
        buf.append(single)
        return

    double = lookup_double(s)
    if double is not None:
        dict_no, idx = double
        buf.append(DICTIONARY_0 + dict_no)
        buf.append(idx)
        return

    if "@" in s:
        # Textual JID form -> structured JID encoding.
        from .jid import parse_jid

        _write_jid(buf, parse_jid(s))
        return

    if _all_in(s, NIBBLE_ALPHABET):
        _write_packed(buf, s, NIBBLE_8, NIBBLE_ALPHABET)
        return

    if _all_in(s, HEX_ALPHABET):
        _write_packed(buf, s, HEX_8, HEX_ALPHABET)
        return

    _write_bytes(buf, s.encode("utf-8"))


def _all_in(s: str, alphabet: str) -> bool:
    if not s:
        return False
    valid = {c for c in alphabet if c != "\x00"}
    return all(c in valid for c in s)


def _write_packed(buf: bytearray, s: str, tag: int, alphabet: str) -> None:
    """Pack two 4-bit symbols per byte.

    The top bit of the length byte signals an odd-length payload (one
    trailing nibble is filler).
    """
    n = len(s)
    odd = n & 1
    header_len = (n + 1) // 2
    if header_len >= 0x80:
        raise ValueError("packed string too long")
    buf.append(tag)
    buf.append((odd << 7) | header_len)
    i = 0
    while i < n:
        hi = alphabet.index(s[i])
        lo = alphabet.index(s[i + 1]) if i + 1 < n else 0x0F
        buf.append((hi << 4) | lo)
        i += 2


def _write_bytes(buf: bytearray, data: bytes) -> None:
    n = len(data)
    if n < 1 << 8:
        buf.append(BINARY_8)
        buf.append(n)
    elif n < 1 << 20:
        buf.append(BINARY_20)
        buf.append((n >> 16) & 0x0F)
        buf.append((n >> 8) & 0xFF)
        buf.append(n & 0xFF)
    elif n < 1 << 32:
        buf.append(BINARY_32)
        buf.extend(n.to_bytes(4, "big"))
    else:
        raise ValueError(f"byte string too long: {n}")
    buf.extend(data)


# --- JIDs -----------------------------------------------------------


_SERVER_TO_AGENT: dict[str, int] = {
    "s.whatsapp.net": 0,
    "lid": 1,
    "hosted": 128,
    "hosted.lid": 129,
}


def _write_jid(buf: bytearray, jid: JID) -> None:
    if jid.device:
        # Agent/device triple: AD_JID, agent byte, device byte, user.
        # The agent byte encodes the domain kind:
        #   s.whatsapp.net -> 0  | lid -> 1
        #   hosted         -> 128 | hosted.lid -> 129
        buf.append(AD_JID)
        buf.append(_SERVER_TO_AGENT.get(jid.server, 0))
        buf.append(jid.device & 0xFF)
        _write_string(buf, jid.user)
        return
    buf.append(JID_PAIR)
    if jid.user:
        _write_string(buf, jid.user)
    else:
        buf.append(LIST_EMPTY)
    _write_string(buf, jid.server)


# Re-export for convenience in debug / tests.
def _debug_raw_payload(node: Node) -> bytes:
    buf = bytearray()
    _write_node(buf, node)
    return bytes(buf)
