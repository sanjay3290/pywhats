# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Group metadata + sender-key message plumbing (issue #39).

Two things groups need beyond 1:1: the participant list (fetched with a
``w:g2`` iq) and the Signal sender-key layer for message content. This
module has the metadata iq/parse and the small helpers that turn a
sender-key session into (or out of) a group ``skmsg`` and the
``SenderKeyDistributionMessage`` that bootstraps it.

Mirrors whatsmeow ``group.go`` (getGroupInfo / parseGroupNode) and
``send.go`` (sendGroup). The sender-key crypto lives in
:mod:`pywhats.signal.experimental.sender_key`.
"""

from __future__ import annotations

from pywhats.binary import Node
from pywhats.binary.jid import parse_jid
from pywhats.events import JID, GroupInfo, GroupParticipant

__all__ = [
    "build_group_info_iq",
    "parse_group_info",
    "GROUP_SERVER",
]

GROUP_SERVER = "g.us"


def build_group_info_iq(group: JID, iq_id: str) -> Node:
    """Build the ``<iq xmlns="w:g2" type="get"><query request="interactive"/></iq>``.

    whatsmeow ``getGroupInfo``: the query is addressed to the group JID.
    """
    return Node(
        tag="iq",
        attrs={"id": iq_id, "type": "get", "xmlns": "w:g2", "to": group},
        content=[Node(tag="query", attrs={"request": "interactive"})],
    )


def parse_group_info(iq: Node) -> GroupInfo:
    """Parse a ``w:g2`` response ``<iq><group>`` into :class:`GroupInfo`.

    Mirrors whatsmeow ``parseGroupNode``: participants carry an optional
    ``type`` of ``admin`` / ``superadmin``.
    """
    group_node = iq.get_child("group")
    if group_node is None:
        raise ValueError("group info response missing <group>")
    group_id = group_node.get_str("id")
    jid = _jid(group_id) if "@" in group_id else JID(user=group_id, server=GROUP_SERVER)

    participants: list[GroupParticipant] = []
    announce = False
    locked = False
    for child in group_node.get_children():
        if child.tag == "participant":
            ptype = child.get_str("type")
            participants.append(
                GroupParticipant(
                    jid=_jid(child.attrs.get("jid")),
                    is_admin=ptype in ("admin", "superadmin"),
                    is_super_admin=ptype == "superadmin",
                )
            )
        elif child.tag == "announcement":
            announce = True
        elif child.tag == "locked":
            locked = True

    owner_attr = group_node.attrs.get("creator")
    return GroupInfo(
        jid=jid,
        subject=group_node.get_str("subject"),
        owner=_jid(owner_attr) if owner_attr is not None else None,
        participants=participants,
        announce=announce,
        locked=locked,
    )


def build_skdm_message_bytes(group_jid: str, axolotl_skdm: bytes) -> bytes:
    """Wrap an axolotl distribution message in a WAE2E Message for fan-out."""
    from pywhats.messaging.padding import pad_random_max16
    from pywhats.proto import Message as MessageProto

    proto = MessageProto()
    proto.sender_key_distribution_message.group_id = group_jid
    proto.sender_key_distribution_message.axolotl_sender_key_distribution_message = axolotl_skdm
    return pad_random_max16(proto.SerializeToString())


def _jid(attr: object) -> JID:
    if isinstance(attr, JID):
        return attr
    if isinstance(attr, str) and attr:
        return parse_jid(attr)
    return JID(user="", server="s.whatsapp.net")
