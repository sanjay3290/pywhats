# SPDX-License-Identifier: Apache-2.0
"""Unit tests for :mod:`pywhats.pairing`.

The server side of the handshake is faked end-to-end: we stand up an
in-memory ``_FakeTransport`` that swaps encoded ``Node`` stanzas with
the :class:`Pairer` under test. No websocket / no real WhatsApp server
is involved.
"""

from __future__ import annotations

import asyncio
import warnings
from typing import Any

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from pywhats.signal.experimental.keys import IdentityKeyPair, xeddsa_sign

from pywhats.binary import Node, decode, encode
from pywhats.errors import PairingFailed
from pywhats.events import JID
from pywhats.pairing import (
    Pairer,
    build_login_payload,
    build_pair_success_reply,
    build_register_payload,
    encode_qr_payload,
    make_fresh_device,
    verify_pair_success,
)
from pywhats.proto import ADVDeviceIdentity, ADVSignedDeviceIdentity, ClientPayload
from pywhats.store import DeviceStore, JIDTuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Bidirectional in-memory queues that look like a NoiseTransport."""

    def __init__(self) -> None:
        self.to_client: asyncio.Queue[bytes] = asyncio.Queue()
        self.from_client: asyncio.Queue[bytes] = asyncio.Queue()

    async def send(self, plaintext: bytes) -> None:
        await self.from_client.put(plaintext)

    async def recv(self) -> bytes:
        return await self.to_client.get()


def _fake_server_adv(
    our_identity_public: bytes,
    *,
    raw_id: int = 2,
    tamper: bool = False,
) -> tuple[ADVSignedDeviceIdentity, IdentityKeyPair]:
    """Build an ADVSignedDeviceIdentity as the primary phone would."""
    server_identity = IdentityKeyPair.generate()
    inner = ADVDeviceIdentity()
    inner.raw_id = raw_id
    inner.timestamp = 1_700_000_000
    inner.key_index = 0
    details = inner.SerializeToString()

    transcript = b"\x06\x00" + details + our_identity_public
    sig = xeddsa_sign(server_identity.private, transcript)

    signed = ADVSignedDeviceIdentity()
    signed.details = details
    signed.account_signature_key = server_identity.public
    signed.account_signature = sig
    if tamper:
        # Flip a bit in the details — signature will no longer verify.
        b = bytearray(signed.details)
        b[0] ^= 0x01
        signed.details = bytes(b)
    return signed, server_identity


def _wrap_adv_hmac(adv: ADVSignedDeviceIdentity, adv_secret: bytes) -> bytes:
    """Wrap a signed ADV identity in the HMAC envelope the server sends."""
    import hmac as _hmac
    from hashlib import sha256

    from pywhats.proto import ADVSignedDeviceIdentityHMAC

    details = adv.SerializeToString()
    mac = _hmac.new(adv_secret, details, sha256).digest()
    w = ADVSignedDeviceIdentityHMAC()
    w.details = details
    w.hmac = mac
    out: bytes = w.SerializeToString()
    return out


def _pair_device_iq(refs: list[str]) -> Node:
    ref_nodes = [Node(tag="ref", content=r.encode("utf-8")) for r in refs]
    return Node(
        tag="iq",
        attrs={"id": "srv-1", "type": "set", "from": "s.whatsapp.net"},
        content=[Node(tag="pair-device", content=ref_nodes)],
    )


def _pair_success_iq(adv: ADVSignedDeviceIdentity, jid_str: str, *, adv_secret: bytes) -> Node:
    return Node(
        tag="iq",
        attrs={"id": "srv-2", "type": "result", "from": "s.whatsapp.net"},
        content=[
            Node(
                tag="pair-success",
                content=[
                    Node(tag="device", attrs={"jid": jid_str}),
                    Node(
                        tag="device-identity",
                        content=_wrap_adv_hmac(adv, adv_secret),
                    ),
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# ClientPayload builders
# ---------------------------------------------------------------------------


def test_register_payload_includes_identity_material() -> None:
    dev = make_fresh_device()
    payload = build_register_payload(dev)
    cp = ClientPayload()
    cp.ParseFromString(payload)
    assert cp.device_pairing_data.e_ident == dev.identity_public
    assert cp.device_pairing_data.e_skey_val == dev.signed_pre_key_public
    assert cp.device_pairing_data.e_skey_sig == dev.signed_pre_key_signature
    assert cp.device_pairing_data.e_regid == dev.registration_id.to_bytes(4, "big")


def test_login_payload_requires_paired_device() -> None:
    dev = make_fresh_device()
    with pytest.raises(PairingFailed):
        build_login_payload(dev)


def test_login_payload_carries_stored_jid() -> None:
    dev = make_fresh_device()
    dev.jid = JIDTuple(user="15551234567", server="s.whatsapp.net", device=2)
    payload = build_login_payload(dev)
    cp = ClientPayload()
    cp.ParseFromString(payload)
    assert cp.username == 15551234567
    assert cp.device == 2
    assert cp.passive is True


# ---------------------------------------------------------------------------
# ADV verification
# ---------------------------------------------------------------------------


def test_verify_pair_success_accepts_valid_signature() -> None:
    dev = make_fresh_device()
    adv, _ = _fake_server_adv(dev.identity_public)
    inner = verify_pair_success(adv, our_identity_public=dev.identity_public)
    assert inner.raw_id == 2


def test_verify_pair_success_rejects_tampered_details() -> None:
    dev = make_fresh_device()
    adv, _ = _fake_server_adv(dev.identity_public, tamper=True)
    with pytest.raises(PairingFailed):
        verify_pair_success(adv, our_identity_public=dev.identity_public)


def test_verify_pair_success_rejects_missing_fields() -> None:
    dev = make_fresh_device()
    empty = ADVSignedDeviceIdentity()
    with pytest.raises(PairingFailed):
        verify_pair_success(empty, our_identity_public=dev.identity_public)


def test_reply_carries_device_signature() -> None:
    dev = make_fresh_device()
    adv, _ = _fake_server_adv(dev.identity_public)
    reply = build_pair_success_reply(
        adv,
        our_identity_private=dev.identity_private,
        our_identity_public=dev.identity_public,
    )
    assert reply.device_signature
    assert reply.details == adv.details
    assert reply.account_signature == adv.account_signature


# ---------------------------------------------------------------------------
# QR payload
# ---------------------------------------------------------------------------


def test_qr_payload_has_four_comma_fields() -> None:
    out = encode_qr_payload(
        "REF-1",
        noise_public=b"\x01" * 32,
        identity_public=b"\x02" * 32,
        adv_secret=b"\x03" * 32,
    )
    parts = out.split(",")
    assert len(parts) == 4
    assert parts[0] == "REF-1"


# ---------------------------------------------------------------------------
# Pairer state machine
# ---------------------------------------------------------------------------


async def test_pairer_happy_path() -> None:
    dev = make_fresh_device()
    transport = _FakeTransport()

    seen_qrs: list[str] = []

    async def on_qr(payload: str) -> None:
        seen_qrs.append(payload)

    pairer = Pairer(
        transport=transport,
        device=dev,
        sleep=lambda _s: asyncio.sleep(0),  # fast-forward ref rotation
        per_ref_interval=0.0,
        first_ref_interval=0.0,
    )

    # Fake server sends pair-device, then pair-success (HMAC-wrapped).
    adv, _ = _fake_server_adv(dev.identity_public)
    await transport.to_client.put(encode(_pair_device_iq(["REF-A", "REF-B"])))
    await transport.to_client.put(
        encode(_pair_success_iq(adv, "15551234567.2@s.whatsapp.net", adv_secret=pairer.adv_secret))
    )
    result = await asyncio.wait_for(pairer.run(on_qr), timeout=2.0)

    assert result.jid.user == "15551234567"
    assert result.jid.device == 2
    assert dev.jid == JIDTuple(user="15551234567", server="s.whatsapp.net", device=2)
    assert dev.device_id == 2
    assert dev.adv_signed_device_identity  # set on success
    # At least the first QR should have been emitted before pair-success.
    assert seen_qrs
    assert seen_qrs[0].startswith("REF-A,")

    # Client must have ack'd the pair-device iq and replied to pair-success.
    ack_frame = await asyncio.wait_for(transport.from_client.get(), timeout=0.1)
    ack_node = decode(ack_frame)
    assert ack_node.tag == "iq"
    assert ack_node.get_str("type") == "result"
    assert ack_node.get_str("id") == "srv-1"

    reply_frame = await asyncio.wait_for(transport.from_client.get(), timeout=0.1)
    reply_node = decode(reply_frame)
    assert reply_node.tag == "iq"
    assert reply_node.get_str("id") == "srv-2"
    # Our reply must wrap the co-signed device-identity.
    sign = reply_node.get_child("pair-device-sign")
    assert sign is not None
    di = sign.get_child("device-identity")
    assert di is not None
    echoed = ADVSignedDeviceIdentity()
    echoed.ParseFromString(di.content_bytes())
    assert echoed.device_signature  # we attached ours
    assert echoed.details == adv.details


async def test_pairer_rejects_tampered_adv() -> None:
    dev = make_fresh_device()
    transport = _FakeTransport()
    pairer = Pairer(
        transport=transport,
        device=dev,
        per_ref_interval=0.0,
        first_ref_interval=0.0,
    )
    adv, _ = _fake_server_adv(dev.identity_public, tamper=True)
    await transport.to_client.put(
        encode(_pair_success_iq(adv, "15551234567.2@s.whatsapp.net", adv_secret=pairer.adv_secret))
    )

    async def on_qr(_p: str) -> None:  # pragma: no cover - not reached
        pass

    with pytest.raises(PairingFailed):
        await asyncio.wait_for(pairer.run(on_qr), timeout=1.0)

    # The device store must NOT have been updated.
    assert dev.jid is None
    assert dev.adv_signed_device_identity is None


async def test_pairer_cancellation_cleans_up() -> None:
    dev = make_fresh_device()
    transport = _FakeTransport()
    # Only send a pair-device iq; never send pair-success. The task will
    # sit on recv() until cancelled.
    await transport.to_client.put(encode(_pair_device_iq(["REF-X"])))

    pairer = Pairer(
        transport=transport,
        device=dev,
        per_ref_interval=0.01,
    )

    async def on_qr(_p: str) -> None:
        pass

    task = asyncio.create_task(pairer.run(on_qr))
    # Give the Pairer time to read the pair-device iq and kick off QR rotation.
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # No persisted state on cancellation.
    assert dev.jid is None
    assert dev.adv_signed_device_identity is None

    # No lingering tasks with the pairing QR name.
    pairing_tasks = [t for t in asyncio.all_tasks() if t.get_name() == "pywhats-pairing-qr"]
    assert pairing_tasks == []


async def test_pairer_times_out_without_pair_success() -> None:
    dev = make_fresh_device()
    transport = _FakeTransport()
    # Feed a stream of non-iq stanzas so recv() returns but the Pairer
    # never sees pair-success. The deadline should fire.
    for _ in range(50):
        await transport.to_client.put(encode(Node(tag="noise")))

    clock_t = [0.0]

    def clock() -> float:
        return clock_t[0]

    async def fast_sleep(s: float) -> None:
        clock_t[0] += s
        await asyncio.sleep(0)

    # Advance the clock on every recv() to simulate time passing.
    real_recv = transport.recv

    async def timed_recv() -> bytes:
        clock_t[0] += 0.5
        return await real_recv()

    transport.recv = timed_recv  # type: ignore[method-assign]

    pairer = Pairer(
        transport=transport,
        device=dev,
        clock=clock,
        sleep=fast_sleep,
        per_ref_interval=0.0,
        total_timeout=5.0,
    )

    async def on_qr(_p: str) -> None:  # pragma: no cover
        pass

    with pytest.raises(PairingFailed):
        await asyncio.wait_for(pairer.run(on_qr), timeout=2.0)


# ---------------------------------------------------------------------------
# Client.connect() routing
# ---------------------------------------------------------------------------


def test_client_routes_by_store_presence(tmp_path: Any) -> None:
    """Client with no saved device should head toward the pairing flow.

    We don't run the full flow here (that needs a real websocket) — we
    just assert that the routing logic consults ``device.jid``.
    """
    from pywhats.client import Client

    c_new = Client()
    assert c_new.device is None  # fresh → pairing path

    dev = make_fresh_device()
    dev.jid = JIDTuple(user="15551234567", server="s.whatsapp.net", device=2)
    path = tmp_path / "dev.json"
    DeviceStore.save(dev, path)

    c_existing = Client(session_path=str(path))
    assert c_existing.device is not None
    assert c_existing.device.jid is not None


# Convenience: make pytest-asyncio run without the deprecation warning on
# the two non-async helpers above when the file is collected.
_ = JID
