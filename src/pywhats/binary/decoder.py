# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Decode wire frames back into :class:`Node` trees.

The layout mirrors :mod:`pywhats.binary.encoder` exactly; see that
module's docstring for the list-header / tokenised-string format.

Prose references consulted (no reference-implementation source read):
  * Public XMPP-over-binary reverse-engineering writeups describing
    the list-header + tokenised-string layout.
"""

from __future__ import annotations

import zlib

from pywhats.events import JID

from .node import AttrValue, Node
from .tokens import (
    AD_JID,
    BINARY_8,
    BINARY_20,
    BINARY_32,
    DICTIONARY_0,
    DICTIONARY_3,
    HEX_8,
    HEX_ALPHABET,
    JID_PAIR,
    LIST_8,
    LIST_16,
    LIST_EMPTY,
    NIBBLE_8,
    NIBBLE_ALPHABET,
    double_token_at,
    single_token_at,
)

__all__ = ["decode"]


class _Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def u8(self) -> int:
        if self.pos >= len(self.buf):
            raise ValueError("unexpected end of buffer")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError("unexpected end of buffer")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def at_end(self) -> bool:
        return self.pos >= len(self.buf)


def decode(buf: bytes) -> Node:
    if len(buf) < 1:
        raise ValueError("frame too short")
    flags = buf[0]
    payload = buf[1:]
    if flags & 0x02:
        payload = zlib.decompress(payload)
    r = _Reader(payload)
    return _read_node(r)


# --- Node readers ---------------------------------------------------


def _read_list_size(r: _Reader, tag: int) -> int:
    if tag == LIST_EMPTY:
        return 0
    if tag == LIST_8:
        return r.u8()
    if tag == LIST_16:
        hi = r.u8()
        lo = r.u8()
        return (hi << 8) | lo
    raise ValueError(f"expected list tag, got {tag}")


def _read_node(r: _Reader) -> Node:
    list_tag = r.u8()
    count = _read_list_size(r, list_tag)
    if count == 0:
        raise ValueError("empty list where a node was expected")
    tag = _read_string(r)
    attrs: dict[str, AttrValue] = {}
    n_attrs = (count - 1) >> 1
    has_content = ((count - 1) & 1) == 1
    for _ in range(n_attrs):
        k = _read_string(r)
        v = _read_attr_value(r)
        attrs[k] = v
    content: bytes | list[Node] | None = None
    if has_content:
        content = _read_content(r)
    return Node(tag=tag, attrs=attrs, content=content)


def _read_content(r: _Reader) -> bytes | list[Node]:
    tag = r.u8()
    if tag in (LIST_EMPTY, LIST_8, LIST_16):
        n = _read_list_size(r, tag)
        return [_read_node(r) for _ in range(n)]
    return _read_byte_payload(r, tag)


# --- Attribute values -----------------------------------------------


def _read_attr_value(r: _Reader) -> AttrValue:
    tag = r.u8()
    if tag == JID_PAIR:
        return _read_jid_pair(r)
    if tag == AD_JID:
        return _read_ad_jid(r)
    v = _read_string_or_bytes(r, tag)
    if isinstance(v, bytes):
        return v.decode("utf-8")
    return v


# --- Strings / bytes ------------------------------------------------


def _read_string(r: _Reader) -> str:
    tag = r.u8()
    v = _read_string_or_bytes(r, tag)
    if isinstance(v, JID):  # pragma: no cover
        raise ValueError("JID found where string expected")
    if isinstance(v, bytes):
        return v.decode("utf-8")
    if isinstance(v, str):
        return v
    raise ValueError("non-string value where string expected")  # pragma: no cover


def _read_string_or_bytes(r: _Reader, tag: int) -> AttrValue | bytes:
    if tag == 0:
        return ""
    if 1 <= tag <= 235:
        return single_token_at(tag)
    if DICTIONARY_0 <= tag <= DICTIONARY_3:
        dict_no = tag - DICTIONARY_0
        idx = r.u8()
        return double_token_at(dict_no, idx)
    return _read_byte_payload(r, tag)


def _read_byte_payload(r: _Reader, tag: int) -> bytes:
    if tag == BINARY_8:
        n = r.u8()
        return r.read(n)
    if tag == BINARY_20:
        b0 = r.u8()
        b1 = r.u8()
        b2 = r.u8()
        n = ((b0 & 0x0F) << 16) | (b1 << 8) | b2
        return r.read(n)
    if tag == BINARY_32:
        n = int.from_bytes(r.read(4), "big")
        return r.read(n)
    if tag == NIBBLE_8:
        return _read_packed(r, NIBBLE_ALPHABET).encode("utf-8")
    if tag == HEX_8:
        return _read_packed(r, HEX_ALPHABET).encode("utf-8")
    raise ValueError(f"unknown string/byte tag {tag}")


def _read_packed(r: _Reader, alphabet: str) -> str:
    header = r.u8()
    odd = (header & 0x80) != 0
    n_bytes = header & 0x7F
    out: list[str] = []
    for i in range(n_bytes):
        b = r.u8()
        hi = (b >> 4) & 0x0F
        lo = b & 0x0F
        out.append(alphabet[hi])
        if not (odd and i == n_bytes - 1):
            out.append(alphabet[lo])
    return "".join(out)


# --- JIDs -----------------------------------------------------------


def _read_jid_pair(r: _Reader) -> JID:
    # User may be LIST_EMPTY (for server-only JIDs).
    peek = r.u8()
    if peek == LIST_EMPTY:
        user = ""
    else:
        v = _read_string_or_bytes(r, peek)
        if isinstance(v, bytes):
            user = v.decode("utf-8")
        elif isinstance(v, str):
            user = v
        else:  # pragma: no cover
            raise ValueError("unexpected JID user type")
    server = _read_string(r)
    return JID(user=user, server=server)


_AGENT_TO_SERVER: dict[int, str] = {
    0: "s.whatsapp.net",
    1: "lid",
    128: "hosted",
    129: "hosted.lid",
}


def _read_ad_jid(r: _Reader) -> JID:
    agent = r.u8()
    device = r.u8()
    user = _read_string(r)
    # The agent byte identifies the JID's domain type:
    #   0   = WhatsApp / phone-number addressing  (@s.whatsapp.net)
    #   1   = LID (Linked-Identity-Domain)        (@lid)
    #   128 = hosted PN                           (@hosted)
    #   129 = hosted LID                          (@hosted.lid)
    # Earlier versions of this decoder collapsed every AD-JID to
    # @s.whatsapp.net, which made LID-keyed inbound messages look like
    # weirdly-numbered PN sessions and broke Signal session lookup.
    server = _AGENT_TO_SERVER.get(agent, "s.whatsapp.net")
    return JID(user=user, server=server, device=device)
