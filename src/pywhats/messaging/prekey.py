# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Fetch Signal prekey bundles via the ``<iq xmlns="encrypt">`` path.

This is the bridge between :class:`pywhats.messaging.Sender` (which
needs a :class:`pywhats.signal.experimental.keys.PreKeyBundle` to start
a Signal session with a new peer) and the WhatsApp server's prekey
publisher endpoint.

The server returns, per queried user::

    <iq type="result" xmlns="encrypt">
      <list>
        <user jid="NNNN@s.whatsapp.net">
          <registration>4-byte BE registration id</registration>
          <identity>32-byte raw Curve25519 identity key</identity>
          <skey>
            <id>3-byte BE spk id</id>
            <value>32-byte raw SPK public</value>
            <signature>64-byte XEdDSA(IK, 0x05||SPK)</signature>
          </skey>
          <key>                                   <!-- optional OPK -->
            <id>3-byte BE opk id</id>
            <value>32-byte raw OPK public</value>
          </key>
        </user>
        ...
      </list>
    </iq>

See Baileys ``Utils/signal.ts:parseAndInjectE2ESessions`` for the
reference shape; the bytes on the wire are verbatim.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from typing import Protocol

from pywhats.binary import Node, encode
from pywhats.errors import PairingFailed  # reused: generic protocol-shape error
from pywhats.events import JID
from pywhats.messaging.ids import new_message_id
from pywhats.messaging.receiver import PendingIqMap
from pywhats.signal.experimental.keys import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPreKey,
    generate_pre_key,
)
from pywhats.signal.experimental.prekey_store import PreKeyStore

__all__ = [
    "fetch_prekey_bundle",
    "build_prekey_query",
    "build_prekey_count_query",
    "build_prekey_upload_node",
    "PrekeyUploader",
    "WANTED_PRE_KEY_COUNT",
    "MIN_PRE_KEY_COUNT",
]

_log = logging.getLogger("pywhats.messaging.prekey")

# whatsmeow prekeys.go: WantedPreKeyCount = 50 (steady-state batch),
# MinPreKeyCount = 5 (refill trigger). whatsmeow uploads 812 on the very
# first upload; we keep the steady-state size by default to stay light.
WANTED_PRE_KEY_COUNT = 50
MIN_PRE_KEY_COUNT = 5

# libsignal Curve25519 key type byte (whatsmeow ecc.DjbType).
_DJB_TYPE = b"\x05"

_SERVER = JID(user="", server="s.whatsapp.net")


def _id3(key_id: int) -> bytes:
    """3-byte big-endian key id (whatsmeow ``keyID[1:]`` of a 4-byte BE id)."""
    return key_id.to_bytes(4, "big")[1:]


class NoiseTransportProtocol(Protocol):
    async def send(self, plaintext: bytes) -> None: ...


def build_prekey_query(jid: JID, iq_id: str) -> Node:
    """Build the ``<iq xmlns="encrypt" type="get">`` for a single JID."""
    return Node(
        tag="iq",
        attrs={
            "id": iq_id,
            "type": "get",
            "xmlns": "encrypt",
            "to": JID(user="", server="s.whatsapp.net"),
        },
        content=[
            Node(
                tag="key",
                content=[Node(tag="user", attrs={"jid": jid})],
            )
        ],
    )


def _read_child_bytes(parent: Node, tag: str) -> bytes:
    child = parent.get_child(tag)
    if child is None:
        raise PairingFailed(f"prekey response missing <{tag}>")
    b = child.content_bytes()
    if not b:
        raise PairingFailed(f"prekey response has empty <{tag}>")
    return b


def _read_int_be(parent: Node, tag: str) -> int:
    return int.from_bytes(_read_child_bytes(parent, tag), "big")


def parse_prekey_response(iq: Node, *, expected_jid: JID) -> PreKeyBundle:
    """Decode a single-user encrypt-iq response into a :class:`PreKeyBundle`."""
    lst = iq.get_child("list")
    if lst is None:
        raise PairingFailed("prekey iq missing <list>")
    users = lst.get_children("user")
    if not users:
        raise PairingFailed("prekey iq list has no <user>")
    user = users[0]

    # Sanity-check that the response is for the JID we asked about.
    returned = user.get_attr("jid")
    if isinstance(returned, JID):
        if returned.user != expected_jid.user:
            raise PairingFailed(
                f"prekey response jid mismatch: got {returned!r} wanted {expected_jid!r}"
            )

    identity_key = _read_child_bytes(user, "identity")
    if len(identity_key) != 32:
        raise PairingFailed(f"prekey identity wrong length: {len(identity_key)}")

    skey = user.get_child("skey")
    if skey is None:
        raise PairingFailed("prekey response missing <skey>")
    spk_id = _read_int_be(skey, "id")
    spk_pub = _read_child_bytes(skey, "value")
    spk_sig = _read_child_bytes(skey, "signature")

    otk = user.get_child("key")
    otk_id: int | None = None
    otk_pub: bytes | None = None
    if otk is not None:
        otk_id = _read_int_be(otk, "id")
        otk_pub = _read_child_bytes(otk, "value")

    bundle = PreKeyBundle(
        identity_key=identity_key,
        signed_pre_key_id=spk_id,
        signed_pre_key_public=spk_pub,
        signed_pre_key_signature=spk_sig,
        one_time_pre_key_id=otk_id,
        one_time_pre_key_public=otk_pub,
    )
    if not bundle.verify_signature():
        raise PairingFailed("prekey bundle SPK signature did not verify")
    return bundle


class PrekeyFetcher:
    """Async callable that resolves a :class:`PreKeyBundle` for a peer JID."""

    def __init__(self, transport: NoiseTransportProtocol, iq_map: PendingIqMap) -> None:
        self._transport = transport
        self._iq_map = iq_map

    async def __call__(self, peer: JID) -> PreKeyBundle:
        iq_id = new_message_id()
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(build_prekey_query(peer, iq_id)))
            result = await fut
        finally:
            self._iq_map.cancel(iq_id)
        return parse_prekey_response(result, expected_jid=peer)


async def fetch_prekey_bundle(
    transport: NoiseTransportProtocol, iq_map: PendingIqMap, peer: JID
) -> PreKeyBundle:
    """One-shot functional form of :class:`PrekeyFetcher`."""
    return await PrekeyFetcher(transport, iq_map)(peer)


# --- one-time prekey count (xmlns="encrypt") -------------------------


def build_prekey_count_query(iq_id: str) -> Node:
    """Build the ``<iq xmlns="encrypt" type="get">`` server OPK-count query.

    whatsmeow ``getServerPreKeyCount`` (prekeys.go): a bare ``<count/>``
    child; the result carries ``<count value="N"/>``.
    """
    return Node(
        tag="iq",
        attrs={"id": iq_id, "type": "get", "xmlns": "encrypt", "to": _SERVER},
        content=[Node(tag="count")],
    )


def parse_prekey_count_response(iq: Node) -> int:
    """Read ``value`` off the ``<count>`` child of a count-query result."""
    count = iq.get_child("count")
    if count is None:
        raise PairingFailed("prekey count iq missing <count>")
    raw = count.get_str("value")
    if not raw:
        raise PairingFailed("prekey count response missing value attr")
    try:
        return int(raw)
    except ValueError as exc:
        raise PairingFailed(f"prekey count value is not an int: {raw!r}") from exc


# --- one-time prekey upload (xmlns="encrypt") ------------------------


def build_prekey_upload_node(
    *,
    registration_id: int,
    identity_public: bytes,
    signed_pre_key: SignedPreKey,
    one_time_pre_keys: Iterable[OneTimePreKey],
    iq_id: str,
) -> Node:
    """Build the ``<iq xmlns="encrypt" type="set">`` that publishes our OPKs.

    Wire shape matches whatsmeow ``uploadPreKeys`` + ``preKeyToNode``
    (prekeys.go): ``<registration>`` (4-byte BE regid), ``<type>`` (the
    single Curve25519 key-type byte 0x05), ``<identity>`` (raw 32-byte
    identity public), ``<list>`` of ``<key><id/><value/></key>`` OPK nodes,
    and a trailing ``<skey>`` carrying the signed prekey plus its
    signature. Each ``<id>`` is the low 3 bytes of the 4-byte big-endian
    key id.
    """
    key_nodes = [
        Node(
            tag="key",
            content=[
                Node(tag="id", content=_id3(opk.key_id)),
                Node(tag="value", content=opk.public),
            ],
        )
        for opk in one_time_pre_keys
    ]
    skey = Node(
        tag="skey",
        content=[
            Node(tag="id", content=_id3(signed_pre_key.key_id)),
            Node(tag="value", content=signed_pre_key.public),
            Node(tag="signature", content=signed_pre_key.signature),
        ],
    )
    return Node(
        tag="iq",
        attrs={"id": iq_id, "type": "set", "xmlns": "encrypt", "to": _SERVER},
        content=[
            Node(tag="registration", content=registration_id.to_bytes(4, "big")),
            Node(tag="type", content=_DJB_TYPE),
            Node(tag="identity", content=identity_public),
            Node(tag="list", content=key_nodes),
            skey,
        ],
    )


class PrekeyUploader:
    """Generate, persist, and upload a batch of one-time prekeys.

    Mirrors whatsmeow ``uploadPreKeys`` (prekeys.go): the private halves
    are kept in ``prekey_store`` so an inbound ``pkmsg`` that references an
    uploaded OPK id can complete X3DH; the public halves are published to
    the server over ``xmlns="encrypt"``.
    """

    def __init__(
        self,
        *,
        transport: NoiseTransportProtocol,
        iq_map: PendingIqMap,
        registration_id: int,
        identity_public: bytes,
        signed_pre_key: SignedPreKey,
        prekey_store: PreKeyStore,
        count: int = WANTED_PRE_KEY_COUNT,
        timeout: float = 20.0,
    ) -> None:
        self._transport = transport
        self._iq_map = iq_map
        self._registration_id = registration_id
        self._identity_public = identity_public
        self._signed_pre_key = signed_pre_key
        self._store = prekey_store
        self._count = count
        self._timeout = timeout

    async def upload(self) -> int:
        """Generate ``count`` fresh OPKs, persist them, and publish them.

        Returns the number of keys uploaded. Ids continue past the highest
        already in the store so a re-upload never reuses an id.
        """
        base = self._store.max_id()
        opks: list[OneTimePreKey] = []
        for offset in range(1, self._count + 1):
            opk = generate_pre_key(base + offset)
            self._store.save(opk)
            opks.append(opk)

        iq_id = new_message_id()
        node = build_prekey_upload_node(
            registration_id=self._registration_id,
            identity_public=self._identity_public,
            signed_pre_key=self._signed_pre_key,
            one_time_pre_keys=opks,
            iq_id=iq_id,
        )
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(node))
            async with asyncio.timeout(self._timeout):
                await fut
        finally:
            self._iq_map.cancel(iq_id)
        _log.info(
            "prekey: uploaded %d one-time prekeys (ids %d..%d)",
            len(opks),
            base + 1,
            base + len(opks),
        )
        return len(opks)

    async def server_count(self) -> int:
        """Query how many of our one-time prekeys the server still holds."""
        iq_id = new_message_id()
        fut = self._iq_map.register(iq_id)
        try:
            await self._transport.send(encode(build_prekey_count_query(iq_id)))
            async with asyncio.timeout(self._timeout):
                result = await fut
        finally:
            self._iq_map.cancel(iq_id)
        return parse_prekey_count_response(result)

    async def refill_if_low(self) -> int:
        """Top up the server's OPK pool when it runs low.

        whatsmeow client.go ``handleConnectSuccess``: the count is checked
        on every connect (the server sometimes fails to notice a dead
        companion, so it is never cached) and ``uploadPreKeys`` fires only
        when it drops below ``MinPreKeyCount``. Returns the number of keys
        uploaded — 0 when the pool is healthy.
        """
        count = await self.server_count()
        if count >= MIN_PRE_KEY_COUNT:
            _log.debug("prekey: server holds %d OPKs (min %d); no refill", count, MIN_PRE_KEY_COUNT)
            return 0
        _log.info("prekey: server holds %d OPKs (min %d); refilling", count, MIN_PRE_KEY_COUNT)
        return await self.upload()
