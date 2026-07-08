# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""USync helpers for resolving WhatsApp multi-device recipients."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from pywhats.binary import Node, encode
from pywhats.binary.jid import parse_jid
from pywhats.errors import PairingFailed
from pywhats.events import JID
from pywhats.messaging.ids import new_message_id
from pywhats.messaging.receiver import PendingIqMap

__all__ = ["USyncDeviceFetcher", "UserSyncEntry", "build_device_query", "parse_device_result"]


class NoiseTransportProtocol(Protocol):
    async def send(self, plaintext: bytes) -> None: ...


@dataclass(frozen=True)
class UserSyncEntry:
    devices: list[JID]
    lid: JID | None = None


def build_device_query(users: Iterable[JID], iq_id: str) -> Node:
    """Build an ``iq`` stanza asking USync for each user's device list."""
    user_nodes = [
        Node(tag="user", attrs={"jid": _base_jid(jid)}) for jid in _dedupe_base_users(users)
    ]
    return Node(
        tag="iq",
        attrs={
            "id": iq_id,
            "type": "get",
            "xmlns": "usync",
            "to": JID(user="", server="s.whatsapp.net"),
        },
        content=[
            Node(
                tag="usync",
                attrs={
                    "context": "message",
                    "mode": "query",
                    "sid": iq_id,
                    "last": "true",
                    "index": "0",
                },
                content=[
                    # Baileys' device-discovery USync is just <devices/>
                    # + <lid/>. We had a third <key/> child here from
                    # before LID landed, but mixing <key/> with <lid/>
                    # makes the WA server silently drop the iq — outbound
                    # send_text would hang forever waiting on a result
                    # that never arrives. Signal prekey bundles come
                    # from a separate `xmlns="encrypt"` iq, not USync.
                    Node(
                        tag="query",
                        content=[
                            Node(tag="devices", attrs={"version": "2"}),
                            Node(tag="lid"),
                        ],
                    ),
                    Node(tag="list", content=user_nodes),
                ],
            )
        ],
    )


def parse_device_result(iq: Node, *, requested_users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
    """Parse a USync device-list response into base-user -> device JIDs."""
    requested = {_base_key(jid): _base_jid(jid) for jid in requested_users}
    out: dict[JID, UserSyncEntry] = {
        base: UserSyncEntry(devices=[base]) for base in requested.values()
    }

    usync = iq.get_child("usync")
    if usync is None:
        raise PairingFailed("usync device response missing <usync>")
    lst = usync.get_child("list")
    if lst is None:
        raise PairingFailed("usync device response missing <list>")

    for user_node in lst.get_children("user"):
        raw_jid = user_node.get_attr("jid")
        base = _jid_from_attr(raw_jid)
        if base.user == "":
            continue
        base = _base_jid(base)
        devices = [_device_jid(base, 0)]

        devices_node = user_node.get_child("devices")
        device_list = devices_node.get_child("device-list") if devices_node is not None else None
        if device_list is not None:
            for child in device_list.get_children("device"):
                dev_id = _read_device_id(child)
                if dev_id is not None:
                    devices.append(_device_jid(base, dev_id))

        out[base] = UserSyncEntry(
            devices=_dedupe_devices(devices),
            lid=_read_lid(user_node),
        )

    return out


class USyncDeviceFetcher:
    """Async callable that resolves complete device lists via ``xmlns=usync``."""

    def __init__(self, transport: NoiseTransportProtocol, iq_map: PendingIqMap) -> None:
        self._transport = transport
        self._iq_map = iq_map

    async def __call__(self, users: Iterable[JID]) -> dict[JID, UserSyncEntry]:
        requested = list(_dedupe_base_users(users))
        iq_id = new_message_id()
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(build_device_query(requested, iq_id)))
            result = await fut
        finally:
            self._iq_map.cancel(iq_id)
        return parse_device_result(result, requested_users=requested)


def _dedupe_base_users(users: Iterable[JID]) -> list[JID]:
    seen: set[tuple[str, str]] = set()
    out: list[JID] = []
    for jid in users:
        base = _base_jid(jid)
        key = _base_key(base)
        if key in seen or not base.user:
            continue
        seen.add(key)
        out.append(base)
    return out


def _dedupe_devices(devices: Iterable[JID]) -> list[JID]:
    seen: set[tuple[str, str, int]] = set()
    out: list[JID] = []
    for jid in devices:
        key = (jid.user, jid.server, jid.device)
        if key in seen:
            continue
        seen.add(key)
        out.append(jid)
    return out


def _read_device_id(node: Node) -> int | None:
    raw = node.get_attr("id")
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return None


def _read_lid(node: Node) -> JID | None:
    lid = node.get_child("lid")
    if lid is None:
        return None
    raw = lid.get_attr("val")
    parsed = _jid_from_attr(raw)
    if parsed.user and parsed.server == "lid":
        return _base_jid(parsed)
    return None


def _base_jid(jid: JID) -> JID:
    return JID(user=jid.user, server=jid.server, device=0)


def _device_jid(base: JID, device: int) -> JID:
    return JID(user=base.user, server=base.server, device=device)


def _base_key(jid: JID) -> tuple[str, str]:
    return (jid.user, jid.server)


def _jid_from_attr(attr: object) -> JID:
    if isinstance(attr, JID):
        return attr
    if isinstance(attr, str) and attr:
        return parse_jid(attr)
    return JID(user="", server="s.whatsapp.net")
