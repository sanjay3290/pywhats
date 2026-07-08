# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Round-trip tests for the NoiseHandshake driver over an in-memory pipe.

Because production :class:`NoiseHandshake` is initiator-only, these tests
build a minimal responder loop that speaks the same XX protobuf envelope
and cryptographic transcript. The responder lives here in the test file
on purpose — it is not part of the shipped API.
"""

from __future__ import annotations

import asyncio

import pytest

from pywhats.errors import HandshakeError
from pywhats.proto import HandshakeMessage
from pywhats.socket.crypto import dh, generate_keypair, private_to_public
from pywhats.socket.noise import (
    DEFAULT_PROLOGUE,
    NOISE_PROTOCOL_AESGCM,
    NOISE_PROTOCOL_CHACHA,
    NoiseHandshake,
    NoiseTransport,
    SymmetricState,
)


class _PipeEnd:
    """One side of an in-memory framed pipe."""

    def __init__(self, inbound: asyncio.Queue[bytes], outbound: asyncio.Queue[bytes]) -> None:
        self._inbound = inbound
        self._outbound = outbound

    async def send_frame(self, payload: bytes) -> None:
        await self._outbound.put(payload)

    async def recv_frame(self) -> bytes:
        return await self._inbound.get()


def _make_pipe() -> tuple[_PipeEnd, _PipeEnd]:
    a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
    b_to_a: asyncio.Queue[bytes] = asyncio.Queue()
    return _PipeEnd(b_to_a, a_to_b), _PipeEnd(a_to_b, b_to_a)


async def _run_responder(
    channel: _PipeEnd,
    *,
    static_priv: bytes,
    prologue: bytes,
    protocol_name: bytes,
    cipher: str,
    server_payload: bytes,
) -> tuple[NoiseTransport, bytes]:
    """Bare-bones responder that completes the XX handshake and returns the
    final transport plus the client payload it received."""
    ss = SymmetricState(protocol_name, cipher)
    ss.mix_hash(prologue)
    s_pub = private_to_public(static_priv)
    e_priv, e_pub = generate_keypair()

    # Leg 1: -> e
    leg1 = await channel.recv_frame()
    msg = HandshakeMessage()
    msg.ParseFromString(leg1)
    re = msg.client_hello.ephemeral
    if len(re) != 32:
        raise AssertionError("bad ephemeral len in leg 1")
    ss.mix_hash(re)
    # WA-variant: skip DecryptAndHash on leg-1 empty payload (no key yet).

    # Leg 2: <- e, ee, s, es + payload
    ss.mix_hash(e_pub)
    ss.mix_key(dh(e_priv, re))
    enc_static = ss.encrypt_and_hash(s_pub)
    ss.mix_key(dh(static_priv, re))
    enc_payload = ss.encrypt_and_hash(server_payload)
    resp = HandshakeMessage(
        server_hello=HandshakeMessage.ServerHello(
            ephemeral=e_pub,
            static=enc_static,
            payload=enc_payload,
        ),
    )
    await channel.send_frame(resp.SerializeToString())

    # Leg 3: -> s, se + encrypted client payload
    leg3 = await channel.recv_frame()
    msg = HandshakeMessage()
    msg.ParseFromString(leg3)
    rs = ss.decrypt_and_hash(msg.client_finish.static)
    ss.mix_key(dh(e_priv, rs))
    client_payload = ss.decrypt_and_hash(msg.client_finish.payload)

    c1, c2 = ss.split()
    # For the responder, c1 is recv-from-initiator and c2 is send-to-initiator.
    transport = NoiseTransport(channel, c2, c1, ss.handshake_hash)
    return transport, client_payload


async def test_xx_handshake_roundtrip_chachapoly() -> None:
    a, b = _make_pipe()
    client_priv, _client_pub = generate_keypair()
    server_priv, _server_pub = generate_keypair()

    handshake = NoiseHandshake(
        a,
        client_static_private=client_priv,
        prologue=DEFAULT_PROLOGUE,
        protocol_name=NOISE_PROTOCOL_CHACHA,
    )
    responder_task = asyncio.create_task(
        _run_responder(
            b,
            static_priv=server_priv,
            prologue=DEFAULT_PROLOGUE,
            protocol_name=NOISE_PROTOCOL_CHACHA,
            cipher="ChaChaPoly",
            server_payload=b"hello-from-server",
        )
    )
    client_transport = await handshake.perform(b"hello-from-client")
    server_transport, received_client_payload = await responder_task

    assert received_client_payload == b"hello-from-client"
    # Matching handshake hashes — channel binding check.
    assert client_transport.handshake_hash == server_transport.handshake_hash

    # Exchange encrypted frames in both directions.
    await client_transport.send(b"ping-1")
    assert await server_transport.recv() == b"ping-1"
    await server_transport.send(b"pong-1")
    assert await client_transport.recv() == b"pong-1"

    # Counter advances monotonically.
    await client_transport.send(b"ping-2")
    assert await server_transport.recv() == b"ping-2"


async def test_xx_handshake_roundtrip_aesgcm() -> None:
    a, b = _make_pipe()
    client_priv, _ = generate_keypair()
    server_priv, _ = generate_keypair()
    handshake = NoiseHandshake(
        a,
        client_static_private=client_priv,
        prologue=DEFAULT_PROLOGUE,
        protocol_name=NOISE_PROTOCOL_AESGCM,
    )
    responder_task = asyncio.create_task(
        _run_responder(
            b,
            static_priv=server_priv,
            prologue=DEFAULT_PROLOGUE,
            protocol_name=NOISE_PROTOCOL_AESGCM,
            cipher="AESGCM",
            server_payload=b"",
        )
    )
    ct = await handshake.perform(b"payload")
    st, cp = await responder_task
    assert cp == b"payload"
    await ct.send(b"x" * 100)
    assert await st.recv() == b"x" * 100


async def test_handshake_fails_on_mismatched_prologue() -> None:
    a, b = _make_pipe()
    client_priv, _ = generate_keypair()
    server_priv, _ = generate_keypair()
    handshake = NoiseHandshake(
        a,
        client_static_private=client_priv,
        prologue=b"WA\x05\x02",
        protocol_name=NOISE_PROTOCOL_CHACHA,
    )
    responder_task = asyncio.create_task(
        _run_responder(
            b,
            static_priv=server_priv,
            prologue=b"WA\x99\x99",  # mismatched
            protocol_name=NOISE_PROTOCOL_CHACHA,
            cipher="ChaChaPoly",
            server_payload=b"",
        )
    )
    with pytest.raises(HandshakeError):
        await handshake.perform(b"payload")
    # Responder may be stuck awaiting a third leg that never comes; cancel it.
    responder_task.cancel()
    try:
        await responder_task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


async def test_handshake_error_does_not_leak_key_material() -> None:
    # Feed the handshake a junk response on leg 2 and make sure the
    # raised HandshakeError message is generic.
    a, b = _make_pipe()
    client_priv, _ = generate_keypair()
    handshake = NoiseHandshake(a, client_static_private=client_priv)

    async def _bad_responder() -> None:
        _ = await b.recv_frame()
        await b.send_frame(b"not a valid protobuf \xff\xff")

    task = asyncio.create_task(_bad_responder())
    with pytest.raises(HandshakeError) as ei:
        await handshake.perform(b"payload")
    await task
    msg = str(ei.value)
    assert "key" not in msg.lower()
    assert "\\x" not in msg
