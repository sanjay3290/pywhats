# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Prekey refill loop: query the server OPK count, top up when low.

Mirrors whatsmeow client.go ``handleConnectSuccess`` + prekeys.go
``getServerPreKeyCount``: the count is checked on every connect and
``uploadPreKeys`` fires only when it drops below ``MinPreKeyCount``.
"""

from __future__ import annotations

import warnings

warnings.simplefilter("ignore", DeprecationWarning)

import asyncio  # noqa: E402

import pytest  # noqa: E402

from pywhats.binary import Node, decode, encode  # noqa: E402
from pywhats.errors import PairingFailed  # noqa: E402
from pywhats.messaging import PendingIqMap  # noqa: E402
from pywhats.messaging.prekey import (  # noqa: E402
    MIN_PRE_KEY_COUNT,
    WANTED_PRE_KEY_COUNT,
    PrekeyUploader,
    build_prekey_count_query,
    parse_prekey_count_response,
)
from pywhats.pairing import make_fresh_device  # noqa: E402
from pywhats.signal.experimental import InMemoryPreKeyStore  # noqa: E402


def test_build_prekey_count_query_shape() -> None:
    node = decode(encode(build_prekey_count_query("IQ1")))

    assert node.tag == "iq"
    assert node.get_str("id") == "IQ1"
    assert node.get_str("type") == "get"
    assert node.get_str("xmlns") == "encrypt"
    assert node.get_child("count") is not None


def test_parse_prekey_count_response_reads_value() -> None:
    iq = Node(
        tag="iq",
        attrs={"id": "IQ1", "type": "result"},
        content=[Node(tag="count", attrs={"value": "42"})],
    )
    assert parse_prekey_count_response(iq) == 42


def test_parse_prekey_count_response_rejects_missing_count() -> None:
    with pytest.raises(PairingFailed):
        parse_prekey_count_response(Node(tag="iq", attrs={"id": "IQ1", "type": "result"}))


def test_parse_prekey_count_response_rejects_garbage_value() -> None:
    iq = Node(
        tag="iq",
        attrs={"id": "IQ1", "type": "result"},
        content=[Node(tag="count", attrs={"value": "many"})],
    )
    with pytest.raises(PairingFailed):
        parse_prekey_count_response(iq)


class _FakeTransport:
    def __init__(self) -> None:
        self.outbound: list[bytes] = []

    async def send(self, plaintext: bytes) -> None:
        self.outbound.append(plaintext)


async def _run_refill(
    server_count: int,
) -> tuple[int, list[Node], InMemoryPreKeyStore]:
    """Drive ``refill_if_low`` against a scripted server.

    The resolver answers each outbound iq: a ``<count/>`` query gets a
    ``<count value=N>`` result, anything else a bare result.
    """
    transport = _FakeTransport()
    iq_map = PendingIqMap()
    device = make_fresh_device()
    store = InMemoryPreKeyStore()
    uploader = PrekeyUploader(
        transport=transport,
        iq_map=iq_map,
        registration_id=device.registration_id,
        identity_public=device.identity_public,
        signed_pre_key=device.signed_pre_key(),
        prekey_store=store,
        timeout=2.0,
    )

    seen: list[Node] = []
    refill = asyncio.create_task(uploader.refill_if_low())

    async def _resolver() -> None:
        idx = 0
        while not refill.done():
            while idx < len(transport.outbound):
                node = decode(transport.outbound[idx])
                idx += 1
                seen.append(node)
                iq_id = node.get_str("id")
                if node.get_child("count") is not None:
                    reply = Node(
                        tag="iq",
                        attrs={"id": iq_id, "type": "result"},
                        content=[Node(tag="count", attrs={"value": str(server_count)})],
                    )
                else:
                    reply = Node(tag="iq", attrs={"id": iq_id, "type": "result"})
                iq_map.resolve(iq_id, reply)
            await asyncio.sleep(0.01)

    resolver = asyncio.create_task(_resolver())
    uploaded = await refill
    await resolver
    return uploaded, seen, store


@pytest.mark.asyncio
async def test_refill_if_low_uploads_when_below_min() -> None:
    uploaded, seen, store = await _run_refill(server_count=MIN_PRE_KEY_COUNT - 1)

    assert uploaded == WANTED_PRE_KEY_COUNT
    # First iq is the count query, second the upload.
    assert seen[0].get_child("count") is not None
    assert seen[1].get_str("type") == "set"
    assert seen[1].get_str("xmlns") == "encrypt"
    lst = seen[1].get_child("list")
    assert lst is not None
    assert len(lst.get_children("key")) == WANTED_PRE_KEY_COUNT
    # Private halves persisted so inbound pkmsgs can complete X3DH.
    assert store.max_id() == WANTED_PRE_KEY_COUNT


@pytest.mark.asyncio
async def test_refill_if_low_skips_when_count_sufficient() -> None:
    # whatsmeow refills strictly below MinPreKeyCount; exactly at the
    # threshold no upload happens.
    uploaded, seen, store = await _run_refill(server_count=MIN_PRE_KEY_COUNT)

    assert uploaded == 0
    assert len(seen) == 1
    assert seen[0].get_child("count") is not None
    assert store.max_id() == 0
