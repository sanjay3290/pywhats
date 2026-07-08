# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Group metadata iq + parse (issue #39).

Mirrors whatsmeow group.go (getGroupInfo / parseGroupNode).
"""

from __future__ import annotations

from pywhats.binary import Node
from pywhats.events import JID
from pywhats.messaging.group import build_group_info_iq, parse_group_info

_GROUP = JID(user="120363000000000000", server="g.us")


def test_build_group_info_iq() -> None:
    node = build_group_info_iq(_GROUP, "iq-1")
    assert node.tag == "iq"
    assert node.get_str("xmlns") == "w:g2"
    assert node.get_str("type") == "get"
    assert node.attrs["to"] == _GROUP
    query = node.get_child("query")
    assert query is not None
    assert query.get_str("request") == "interactive"


def test_parse_group_info() -> None:
    group_node = Node(
        tag="group",
        attrs={
            "id": "120363000000000000",
            "subject": "Test Group",
            "creator": "111@s.whatsapp.net",
        },
        content=[
            Node(tag="participant", attrs={"jid": "111@s.whatsapp.net", "type": "superadmin"}),
            Node(tag="participant", attrs={"jid": "222@s.whatsapp.net", "type": "admin"}),
            Node(tag="participant", attrs={"jid": "333@s.whatsapp.net"}),
            Node(tag="announcement"),
        ],
    )
    iq = Node(tag="iq", attrs={"type": "result"}, content=[group_node])
    info = parse_group_info(iq)

    assert info.subject == "Test Group"
    assert info.jid.user == "120363000000000000"
    assert info.owner is not None and info.owner.user == "111"
    assert info.announce is True
    assert len(info.participants) == 3
    assert info.participants[0].is_super_admin is True
    assert info.participants[0].is_admin is True
    assert info.participants[1].is_admin is True
    assert info.participants[2].is_admin is False


def test_parse_group_info_missing_group_raises() -> None:
    import pytest

    iq = Node(tag="iq", attrs={"type": "result"})
    with pytest.raises(ValueError, match="group"):
        parse_group_info(iq)
