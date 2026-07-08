# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Round-trip and behavioural tests for :mod:`pywhats.binary`."""

from __future__ import annotations

import pytest

from pywhats.binary import Node, decode, encode
from pywhats.binary.jid import jid_to_str, parse_jid
from pywhats.events import JID


def _rt(node: Node, compress: bool = False) -> Node:
    return decode(encode(node, compress=compress))


# --- Primitive node shapes ------------------------------------------


def test_empty_content_node() -> None:
    n = Node("iq", {"type": "get", "id": "abc.123"})
    out = _rt(n)
    assert out == n


def test_bytes_content_node() -> None:
    n = Node("enc", {"type": "pkmsg"}, b"\x01\x02\x03\x04\x05")
    out = _rt(n)
    assert out == n


def test_empty_bytes_content() -> None:
    n = Node("ping", {}, b"")
    out = _rt(n)
    assert out == n


def test_no_attrs_no_content() -> None:
    n = Node("success")
    out = _rt(n)
    assert out == n


# --- Children -------------------------------------------------------


def test_nested_children() -> None:
    n = Node(
        "iq",
        {"type": "set", "id": "abc"},
        [
            Node("pair-device", {}, [Node("ref", {}, b"ref-bytes-1")]),
        ],
    )
    out = _rt(n)
    assert out == n


def test_empty_child_list() -> None:
    n = Node("stream", {}, [])
    out = _rt(n)
    assert out == n


# --- Strings (token / packed / raw) ---------------------------------


def test_single_byte_tokens_are_compact() -> None:
    # Pure-token node should produce a tiny frame.
    n = Node("iq", {"type": "get", "xmlns": "w"})
    frame = encode(n)
    # flags + LIST_8 + count + tag + type + get + xmlns + w(double-byte) = 9 bytes.
    assert len(frame) == 9


def test_nibble_packed_digits() -> None:
    n = Node("receipt", {"id": "1234567890"})
    out = _rt(n)
    assert out == n


def test_hex_packed_upper() -> None:
    n = Node("iq", {"id": "ABCDEF0123"})
    out = _rt(n)
    assert out == n


def test_utf8_fallback() -> None:
    n = Node("msg", {"body": "hello world, \u00e9\u00e0"})
    out = _rt(n)
    assert out == n


def test_large_bytes_binary20() -> None:
    big = bytes(range(256)) * 5  # 1280 bytes -> BINARY_20 path
    n = Node("media", {}, big)
    out = _rt(n)
    assert out == n


# --- JIDs -----------------------------------------------------------


def test_bare_user_jid() -> None:
    n = Node("iq", {"to": JID(user="1555", server="s.whatsapp.net")})
    out = _rt(n)
    assert out == n


def test_user_device_jid() -> None:
    n = Node("msg", {"from": JID(user="1555", server="s.whatsapp.net", device=2)})
    out = _rt(n)
    assert out == n


def test_group_jid() -> None:
    n = Node("iq", {"to": JID(user="12345-67890", server="g.us")})
    out = _rt(n)
    assert out == n


def test_lid_jid() -> None:
    n = Node("iq", {"to": JID(user="99887766", server="lid")})
    out = _rt(n)
    assert out == n


def test_lid_device_jid_round_trips_under_ad_jid() -> None:
    # AD-JID encoding: agent byte must be 1 for @lid, 0 for @s.whatsapp.net.
    # If round-trip collapses agent==1 to s.whatsapp.net, every layer above
    # binary builds the wrong Signal session address.
    n = Node("msg", {"from": JID(user="111222333444555", server="lid", device=5)})
    out = _rt(n)
    assert out == n


def test_hosted_jid_round_trip() -> None:
    n = Node("iq", {"to": JID(user="1555", server="hosted", device=3)})
    out = _rt(n)
    assert out == n


def test_server_only_jid() -> None:
    n = Node("iq", {"to": JID(user="", server="s.whatsapp.net")})
    out = _rt(n)
    assert out == n


def test_parse_jid_roundtrip() -> None:
    for s in (
        "1555@s.whatsapp.net",
        "1555.2@s.whatsapp.net",
        "12345-67890@g.us",
        "s.whatsapp.net",
    ):
        assert jid_to_str(parse_jid(s)) == s


# --- Compression ----------------------------------------------------


def test_compressed_frame_roundtrip() -> None:
    n = Node(
        "batch",
        {"type": "set"},
        [Node("item", {"n": str(i)}, b"x" * 64) for i in range(20)],
    )
    out = _rt(n, compress=True)
    assert out == n


def test_compression_flag_bit() -> None:
    n = Node("iq", {"type": "get"})
    plain = encode(n)
    comp = encode(n, compress=True)
    assert plain[0] & 0x02 == 0
    assert comp[0] & 0x02 == 0x02


# --- Realistic Phase 1 fixtures (20+ nodes total) -------------------


FIXTURES: list[Node] = [
    Node("iq", {"id": "1", "type": "get", "xmlns": "w:p"}),
    Node("iq", {"id": "2", "type": "set"}, [Node("pair-device")]),
    Node(
        "iq",
        {"id": "3", "type": "result"},
        [Node("pair-success", {}, [Node("ref", {}, b"abc")])],
    ),
    Node("presence", {"type": "available"}),
    Node("presence", {"type": "unavailable"}),
    Node(
        "message",
        {
            "to": JID(user="1555", server="s.whatsapp.net"),
            "id": "MSGID01",
            "type": "text",
        },
        [Node("body", {}, b"hello")],
    ),
    Node(
        "message",
        {
            "to": JID(user="group1", server="g.us"),
            "id": "MSGID02",
            "type": "text",
            "participant": JID(user="1555", server="s.whatsapp.net"),
        },
        [Node("body", {}, b"group hello")],
    ),
    Node(
        "receipt",
        {
            "id": "MSGID01",
            "from": JID(user="1555", server="s.whatsapp.net"),
            "t": "1700000000",
        },
    ),
    Node(
        "receipt",
        {
            "id": "MSGID02",
            "type": "read",
            "from": JID(user="1555", server="s.whatsapp.net"),
        },
    ),
    Node("notification", {"type": "server-sync"}),
    Node("ack", {"id": "MSGID01", "class": "receipt"}),
    Node("stream:error", {}, [Node("text", {}, b"boom")]),
    Node("success", {"lg": "en", "lc": "US", "creation": "1700000000"}),
    Node("failure", {"reason": "401"}),
    Node(
        "iq",
        {"id": "4", "type": "set", "xmlns": "w:g2"},
        [Node("create", {"subject": "Team"})],
    ),
    Node("chatstate", {"from": JID(user="1555", server="s.whatsapp.net")}),
    Node("call", {"id": "callid", "from": JID(user="1555", server="s.whatsapp.net")}),
    Node(
        "enc",
        {"type": "pkmsg", "v": "2"},
        bytes(range(32)),
    ),
    Node(
        "enc",
        {"type": "msg", "v": "2"},
        bytes(range(16, 80)),
    ),
    Node(
        "iq",
        {"id": "5", "type": "get", "xmlns": "w:profile:picture"},
        [Node("picture", {"type": "image"})],
    ),
    Node(
        "message",
        {
            "to": JID(user="1555", server="s.whatsapp.net", device=3),
            "id": "MSGID03",
            "type": "text",
        },
        [Node("body", {}, b"device-targeted")],
    ),
    Node(
        "notification",
        {"type": "devices"},
        [
            Node(
                "list",
                {},
                [
                    Node("device", {"jid": JID(user="1555", server="s.whatsapp.net", device=1)}),
                    Node("device", {"jid": JID(user="1555", server="s.whatsapp.net", device=2)}),
                ],
            ),
        ],
    ),
]


@pytest.mark.parametrize("idx", range(len(FIXTURES)))
def test_fixture_roundtrip(idx: int) -> None:
    n = FIXTURES[idx]
    assert decode(encode(n)) == n


@pytest.mark.parametrize("idx", range(len(FIXTURES)))
def test_fixture_roundtrip_compressed(idx: int) -> None:
    n = FIXTURES[idx]
    assert decode(encode(n, compress=True)) == n


def test_all_fixtures_count() -> None:
    assert len(FIXTURES) >= 20


# --- Node helpers ---------------------------------------------------


def test_node_helpers() -> None:
    n = Node(
        "iq",
        {"id": "42", "type": "result"},
        [Node("a"), Node("b"), Node("a", {"x": "1"})],
    )
    assert n.get_attr("type") == "result"
    assert n.get_str("id") == "42"
    assert len(n.get_children()) == 3
    assert len(n.get_children("a")) == 2
    assert n.get_child("b") is not None
    assert n.get_child("missing") is None


# --- Error paths ----------------------------------------------------


def test_decode_short_frame() -> None:
    with pytest.raises(ValueError):
        decode(b"")


def test_encode_unsupported_attr() -> None:
    with pytest.raises(TypeError):
        encode(Node("x", {"k": 1.5}))  # type: ignore[dict-item]
