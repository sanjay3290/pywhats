# SPDX-License-Identifier: Apache-2.0
"""Tests for USync device-list parsing."""

from __future__ import annotations

from pywhats.binary import Node
from pywhats.events import JID
from pywhats.messaging.usync import build_device_query, parse_device_result


def test_build_device_query_shape() -> None:
    node = build_device_query([JID(user="15551234567")], "IQ1")

    assert node.tag == "iq"
    assert node.get_str("xmlns") == "usync"
    usync = node.get_child("usync")
    assert usync is not None
    assert usync.get_str("context") == "message"
    query = usync.get_child("query")
    assert query is not None
    devices = query.get_child("devices")
    assert devices is not None
    assert devices.get_str("version") == "2"
    assert query.get_child("lid") is not None
    # No <key/> child — Signal prekey bundles come via a separate
    # xmlns="encrypt" iq, and mixing <key/> with <lid/> in the same
    # USync query makes the WA server silently drop the iq.
    assert query.get_child("key") is None


def test_parse_device_result_includes_primary_and_secondaries() -> None:
    base = JID(user="15551234567", server="s.whatsapp.net")
    iq = Node(
        tag="iq",
        attrs={"id": "IQ1", "type": "result"},
        content=[
            Node(
                tag="usync",
                content=[
                    Node(
                        tag="list",
                        content=[
                            Node(
                                tag="user",
                                attrs={"jid": base},
                                content=[
                                    Node(
                                        tag="devices",
                                        content=[
                                            Node(
                                                tag="device-list",
                                                content=[
                                                    Node(tag="device", attrs={"id": "0"}),
                                                    Node(tag="device", attrs={"id": "12"}),
                                                ],
                                            )
                                        ],
                                    ),
                                    Node(tag="lid", attrs={"val": "111222333444555@lid"}),
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    parsed = parse_device_result(iq, requested_users=[base])

    assert parsed[base].devices == [
        JID(user="15551234567", server="s.whatsapp.net", device=0),
        JID(user="15551234567", server="s.whatsapp.net", device=12),
    ]
    assert parsed[base].lid == JID(user="111222333444555", server="lid")
