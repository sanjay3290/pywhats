# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Responder-side Noise XX for the offline fake WhatsApp server.

This is a *test double*, not a second protocol implementation: it reuses
the client's own :class:`~pywhats.socket.noise.HandshakeState`,
:class:`~pywhats.socket.noise.CipherState`, and
:class:`~pywhats.socket.noise.NoiseTransport` classes verbatim. Only the
two role-specific Diffie-Hellman tokens (``es`` / ``se``) differ between
the XX initiator and responder, so we subclass ``HandshakeState`` and
override just those.

The client drives the initiator legs inside
:meth:`pywhats.socket.noise.NoiseHandshake.perform`; this module drives
the mirror-image responder legs:

    leg 1  <- e            (read the client's ephemeral)
    leg 2  -> e, ee, s, es (send our ephemeral + encrypted static)
    leg 3  <- s, se        (read the client's static + payload)
"""

from __future__ import annotations

from pywhats.proto import HandshakeMessage
from pywhats.socket.crypto import DHLEN, dh
from pywhats.socket.noise import (
    DEFAULT_PROLOGUE,
    NOISE_PROTOCOL_AESGCM,
    HandshakeState,
    NoiseTransport,
)

# AEAD tag length for both supported ciphers (mirrors noise._TAG_LEN,
# which is module-private).
TAG_LEN = 16


class _ResponderHandshakeState(HandshakeState):
    """XX responder: the ``es`` / ``se`` DH inputs mirror the initiator's.

    Noise 5.3: ``es`` is always DH(e_initiator, s_responder) and ``se``
    is DH(s_initiator, e_responder). The base class computes those from
    the initiator's point of view; the responder holds the opposite ends
    of each pair.
    """

    def _dh_es(self) -> bytes:
        # Responder: es = DH(own static, remote ephemeral).
        assert self._re is not None
        return dh(self._s.private, self._re)

    def _dh_se(self) -> bytes:
        # Responder: se = DH(own ephemeral, remote static).
        assert self._e is not None and self._rs is not None
        return dh(self._e.private, self._rs)


class _FrameChannelProto:
    """Structural type: what the responder needs from the framed socket."""

    async def send_frame(self, payload: bytes) -> None: ...  # pragma: no cover
    async def recv_frame(self) -> bytes: ...  # pragma: no cover


class ServerHandshake:
    """Drive the XX handshake from the responder side over a framed channel.

    Returns a :class:`~pywhats.socket.noise.NoiseTransport` on success,
    plus the raw client ``ClientPayload`` bytes carried in leg 3 so the
    caller can tell a register handshake from a login handshake.
    """

    def __init__(
        self,
        channel: _FrameChannelProto,
        *,
        server_static_private: bytes,
        prologue: bytes = DEFAULT_PROLOGUE,
        protocol_name: bytes = NOISE_PROTOCOL_AESGCM,
    ) -> None:
        cipher = "AESGCM" if protocol_name == NOISE_PROTOCOL_AESGCM else "ChaChaPoly"
        self._channel = channel
        self._state = _ResponderHandshakeState(
            protocol_name=protocol_name,
            cipher=cipher,
            prologue=prologue,
            local_static_private=server_static_private,
        )

    async def perform(self, server_payload: bytes = b"") -> tuple[NoiseTransport, bytes]:
        # --- leg 1: <- e ------------------------------------------------
        leg1 = await self._channel.recv_frame()
        hm1 = HandshakeMessage()
        hm1.ParseFromString(leg1)
        client_ephemeral = hm1.client_hello.ephemeral
        payload1, split = self._state.read_message(client_ephemeral)
        assert split is None, "unexpected split on leg 1"
        _ = payload1

        # --- leg 2: -> e, ee, s, es ------------------------------------
        leg2_bytes, split = self._state.write_message(server_payload)
        assert split is None, "unexpected split on leg 2"
        ephemeral = leg2_bytes[:DHLEN]
        enc_static = leg2_bytes[DHLEN : DHLEN + DHLEN + TAG_LEN]
        enc_payload = leg2_bytes[DHLEN + DHLEN + TAG_LEN :]
        hm2 = HandshakeMessage(
            server_hello=HandshakeMessage.ServerHello(
                ephemeral=ephemeral,
                static=enc_static,
                payload=enc_payload,
            )
        )
        await self._channel.send_frame(hm2.SerializeToString())

        # --- leg 3: <- s, se + encrypted client payload ----------------
        leg3 = await self._channel.recv_frame()
        hm3 = HandshakeMessage()
        hm3.ParseFromString(leg3)
        finish = hm3.client_finish
        client_payload, split = self._state.read_message(finish.static + finish.payload)
        assert split is not None, "handshake did not complete on leg 3"

        c1, c2 = split
        # Noise 5.2: initiator send = c1 / recv = c2; the responder is the
        # mirror image, so our send = c2 and recv = c1.
        transport = NoiseTransport(self._channel, c2, c1, self._state.handshake_hash)
        return transport, client_payload
