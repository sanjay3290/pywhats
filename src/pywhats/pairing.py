# SPDX-License-Identifier: Apache-2.0
"""QR pairing and login-resume orchestration.

This module is the glue between the Noise transport (``pywhats.socket``),
the XMPP-over-binary node codec (``pywhats.binary``), the protobuf
schemas (``pywhats.proto``), and the persistent credential store
(``pywhats.store``).

Two flows:

* :class:`Pairer` — used when no credentials exist. Runs the Noise XX
  handshake with a freshly-generated static keypair, sends a
  ``ClientPayload`` marked as a companion-device registration, and then
  consumes server stanzas waiting for the ``pair-device`` iq (which
  carries the rotating QR ref strings) followed by a ``pair-success``
  iq (which carries the signed ``ADVSignedDeviceIdentity`` the primary
  phone hands us once the user scans). The signature on that identity
  is verified before anything is persisted.
* :func:`login` — used when credentials already exist. Reuses the
  stored Noise static key and ADV identity blob so the server accepts
  us as an already-registered companion.

Prose references consulted (public writeups only — no client-source
reverse engineering):

* WhatsApp Web / multi-device protocol overview posts describing the
  ``pair-device`` iq with nested ``ref`` elements, the rotation cadence,
  and the ``pair-success`` response carrying the ADV blob.
* The public Noise Protocol specification for the handshake transcript
  these messages travel over.

Unknowns / risk areas (all marked inline with ``TODO``):

* The exact attribute names on the ``iq`` / ``pair-device`` /
  ``pair-success`` stanzas are not documented by Meta. Field names used
  here (``id``, ``type``, ``to``, ``from``, ``xmlns``) follow the
  general XMPP convention that the writeups describe but a live capture
  may disagree.
* The encoding of the QR ref payload (what we hand to the consumer as
  the string the user scans) follows the four-field convention seen in
  public writeups: ``ref,noise_pub_b64,identity_pub_b64,adv_secret_b64``.
* Server-pushed iq stanzas may use ``type="set"`` or ``type="get"``;
  both are accepted here.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from pywhats.binary import Node, decode, encode
from pywhats.binary.jid import parse_jid
from pywhats.errors import PairingFailed
from pywhats.events import JID
from pywhats.proto import (
    ADVDeviceIdentity,
    ADVSignedDeviceIdentity,
    ADVSignedDeviceIdentityHMAC,
    ClientPayload,
    DevicePairingRegistrationData,
    DeviceProps,
    UserAgent,
    WebInfo,
)
from pywhats.signal.experimental.keys import (
    IdentityKeyPair,
    SignedPreKey,
    xeddsa_sign,
    xeddsa_verify,
)
from pywhats.socket.crypto import generate_keypair
from pywhats.store import DeviceStore, JIDTuple
from pywhats.version import (
    DEFAULT_PAIRING_NAME,
    QR_REF_INTERVAL_SECONDS,
    QR_TOTAL_TIMEOUT_SECONDS,
    WA_WEB_VERSION,
)

__all__ = [
    "PairResult",
    "Pairer",
    "build_login_payload",
    "build_register_payload",
    "build_pair_success_reply",
    "verify_pair_success",
]

_log = logging.getLogger("pywhats.pairing")

# Handler the Pairer calls for each emitted QR ref. Async so that
# consumers can drive a renderer (terminal / websocket push / etc.)
# without blocking the receive loop.
QRCallback = Callable[[str], Awaitable[None]]

# ADV HMAC context strings — the public writeups describe two byte
# strings that are mixed in when deriving the device-signature
# transcript on the companion side. These are the conventional values
# seen in prose writeups. TODO: verify against a fresh capture.
_ADV_ACCOUNT_SIG_PREFIX = b"\x06\x00"
_ADV_DEVICE_SIG_PREFIX = b"\x06\x01"


# ---------------------------------------------------------------------------
# ClientPayload builders
# ---------------------------------------------------------------------------


def _user_agent() -> UserAgent:
    ua = UserAgent()
    ua.platform = UserAgent.Platform.WEB
    ua.release_channel = UserAgent.ReleaseChannel.RELEASE
    ua.app_version.primary = WA_WEB_VERSION[0]
    ua.app_version.secondary = WA_WEB_VERSION[1]
    ua.app_version.tertiary = WA_WEB_VERSION[2]
    ua.mcc = "000"
    ua.mnc = "000"
    ua.os_version = "0.1"
    ua.manufacturer = ""
    ua.device = "Desktop"
    ua.os_build_number = "0.1"
    ua.locale_language_iso_639_1 = "en"
    ua.locale_country_iso_3166_1_alpha_2 = "US"
    return ua


def _web_info() -> WebInfo:
    wi = WebInfo()
    wi.web_sub_platform = WebInfo.WebSubPlatform.WEB_BROWSER
    return wi


def _device_props(pairing_name: str) -> bytes:
    dp = DeviceProps()
    # Baileys pairs as a browser. Matching its os/platform triple avoids
    # server-side validation edge cases we've hit with plain "pywhats" +
    # DESKTOP — the server evidently routes browser-tier pairing through
    # a different path and bounces anything else with a vague
    # "can't link, expired" on the phone.
    dp.os = "Mac OS"
    dp.platform_type = DeviceProps.PlatformType.CHROME
    dp.requires_full_sync = False
    dp.version.primary = 10
    dp.version.secondary = 15
    dp.version.tertiary = 7
    return bytes(dp.SerializeToString())


def _build_hash() -> bytes:
    """MD5 of the dotted WA web version — matches Baileys/WA wire format."""
    return hashlib.md5(".".join(str(p) for p in WA_WEB_VERSION).encode()).digest()


def build_register_payload(
    device: DeviceStore,
    *,
    pairing_name: str = DEFAULT_PAIRING_NAME,
    build_hash: bytes | None = None,
) -> bytes:
    """Build the ``ClientPayload`` sent during companion registration.

    This runs inside the final leg of the Noise XX handshake and is what
    the server uses to decide whether to route us into the pair-device
    flow.
    """
    cp = ClientPayload()
    cp.passive = False
    cp.pull = False
    cp.connect_type = ClientPayload.ConnectType.WIFI_UNKNOWN
    cp.connect_reason = ClientPayload.ConnectReason.USER_ACTIVATED
    cp.user_agent.CopyFrom(_user_agent())
    cp.web_info.CopyFrom(_web_info())

    reg = DevicePairingRegistrationData()
    reg.e_regid = device.registration_id.to_bytes(4, "big")
    reg.e_keytype = b"\x05"  # Curve25519 type byte — conventional.
    reg.e_ident = device.identity_public
    reg.e_skey_id = device.signed_pre_key_id.to_bytes(3, "big")
    reg.e_skey_val = device.signed_pre_key_public
    reg.e_skey_sig = device.signed_pre_key_signature
    reg.build_hash = build_hash if build_hash is not None else _build_hash()
    reg.device_props = _device_props(pairing_name)
    cp.device_pairing_data.CopyFrom(reg)
    return bytes(cp.SerializeToString())


def build_login_payload(device: DeviceStore) -> bytes:
    """Build the ``ClientPayload`` for the resume / login flow."""
    if device.jid is None:
        raise PairingFailed("cannot build login payload — device is not paired")
    cp = ClientPayload()
    try:
        cp.username = int(device.jid.user)
    except ValueError as exc:
        raise PairingFailed("stored JID user is not numeric") from exc
    cp.device = device.jid.device
    cp.passive = True
    cp.pull = True
    cp.connect_type = ClientPayload.ConnectType.WIFI_UNKNOWN
    cp.connect_reason = ClientPayload.ConnectReason.USER_ACTIVATED
    cp.user_agent.CopyFrom(_user_agent())
    cp.web_info.CopyFrom(_web_info())
    return bytes(cp.SerializeToString())


# ---------------------------------------------------------------------------
# ADV signature verification
# ---------------------------------------------------------------------------


def verify_pair_success(
    signed_identity: ADVSignedDeviceIdentity,
    *,
    our_identity_public: bytes,
) -> ADVDeviceIdentity:
    """Verify the ``ADVSignedDeviceIdentity`` handed back by the phone.

    Raises :class:`PairingFailed` if the signature is malformed or
    doesn't verify against the account signature key the server sent.

    Returns the parsed inner ``ADVDeviceIdentity`` so the caller can
    extract the assigned device id.
    """
    if not signed_identity.details:
        raise PairingFailed("pair-success payload missing details")
    if not signed_identity.account_signature:
        raise PairingFailed("pair-success payload missing account signature")
    if not signed_identity.account_signature_key:
        raise PairingFailed("pair-success payload missing account signature key")

    # Transcript for the account signature (Baileys Curve.verify, raw keys):
    # prefix || details || our_identity_public (32 raw bytes, no type byte).
    transcript = _ADV_ACCOUNT_SIG_PREFIX + signed_identity.details + our_identity_public
    acct_sig_key = signed_identity.account_signature_key
    if len(acct_sig_key) == 33 and acct_sig_key[0] == 0x05:
        acct_sig_key = acct_sig_key[1:]
    if not xeddsa_verify(
        acct_sig_key,
        transcript,
        signed_identity.account_signature,
    ):
        raise PairingFailed("ADV account signature did not verify")

    inner = ADVDeviceIdentity()
    try:
        inner.ParseFromString(signed_identity.details)
    except Exception as exc:  # noqa: BLE001 — protobuf raises many types
        raise PairingFailed("ADV details are not a valid ADVDeviceIdentity") from exc
    return inner


def build_pair_success_reply(
    signed_identity: ADVSignedDeviceIdentity,
    *,
    our_identity_private: bytes,
    our_identity_public: bytes,
) -> ADVSignedDeviceIdentity:
    """Co-sign the ADV identity and return the blob to echo back.

    The companion adds a device-signature computed over the same details
    field with a different prefix. The server expects this echo so it
    knows we accepted the pairing.
    """
    transcript = (
        _ADV_DEVICE_SIG_PREFIX
        + signed_identity.details
        + our_identity_public
        + signed_identity.account_signature_key
    )
    dev_sig = xeddsa_sign(our_identity_private, transcript)
    # Echo the identity back WITHOUT account_signature_key (Baileys strips
    # it when re-encoding the reply — the server holds that key and
    # rejects a response that re-sends it).
    reply = ADVSignedDeviceIdentity()
    reply.details = signed_identity.details
    reply.account_signature = signed_identity.account_signature
    reply.device_signature = dev_sig
    return reply


# ---------------------------------------------------------------------------
# QR ref string helpers
# ---------------------------------------------------------------------------


@dataclass
class _QRRef:
    ref: str
    expires_at: float


def encode_qr_payload(
    ref: str,
    *,
    noise_public: bytes,
    identity_public: bytes,
    adv_secret: bytes,
) -> str:
    """Format the string the consumer turns into a QR image.

    The format is four comma-separated fields: ``ref,noise,identity,adv``
    where the latter three are standard base64 (padded).
    """
    return ",".join(
        [
            ref,
            base64.b64encode(noise_public).decode("ascii"),
            base64.b64encode(identity_public).decode("ascii"),
            base64.b64encode(adv_secret).decode("ascii"),
        ]
    )


# ---------------------------------------------------------------------------
# Stanza parsing
# ---------------------------------------------------------------------------


def _extract_pair_device_refs(iq: Node) -> list[str]:
    """Pull the list of ref strings out of a ``pair-device`` iq.

    The public writeups describe the structure as::

        <iq id="..." type="set" from="s.whatsapp.net">
          <pair-device>
            <ref>XXXX</ref>
            <ref>YYYY</ref>
            ...
          </pair-device>
        </iq>

    TODO: confirm the attribute names ``id`` / ``type`` / ``from``
    against a fresh wire capture.
    """
    pd = iq.get_child("pair-device")
    if pd is None:
        raise PairingFailed("iq missing pair-device child")
    refs: list[str] = []
    for child in pd.get_children("ref"):
        raw = child.content_bytes()
        if not raw:
            continue
        try:
            refs.append(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise PairingFailed("pair-device ref is not valid UTF-8") from exc
    if not refs:
        raise PairingFailed("pair-device iq carried no refs")
    return refs


def _extract_pair_success(
    iq: Node, *, adv_secret: bytes
) -> tuple[Node, ADVSignedDeviceIdentity, JID, int]:
    """Pull the signed ADV blob + assigned JID out of a ``pair-success`` iq.

    Returns ``(pair_success_node, parsed_adv, assigned_jid, device_id)``.
    The writeups describe the structure as::

        <iq id="..." type="result" from="s.whatsapp.net">
          <pair-success>
            <device jid="15551234567.2@s.whatsapp.net" />
            <device-identity>...serialised ADVSignedDeviceIdentity...</device-identity>
            <platform name="..." />    <!-- optional -->
            <business name="..." />    <!-- optional -->
          </pair-success>
        </iq>

    TODO: confirm element names against a fresh capture. The
    ``device-identity`` payload is the only element we strictly need.
    """
    ps = iq.get_child("pair-success")
    if ps is None:
        raise PairingFailed("iq missing pair-success child")
    di = ps.get_child("device-identity")
    if di is None:
        raise PairingFailed("pair-success missing device-identity")
    blob = di.content_bytes()
    if not blob:
        raise PairingFailed("pair-success device-identity is empty")

    # device-identity carries an ADVSignedDeviceIdentityHMAC wrapper:
    # { details: ADVSignedDeviceIdentity_bytes, hmac: 32B, accountType? }.
    # We verify the HMAC with adv_secret, then decode details.
    hmac_wrapper = ADVSignedDeviceIdentityHMAC()
    try:
        hmac_wrapper.ParseFromString(blob)
    except Exception as exc:  # noqa: BLE001
        raise PairingFailed("pair-success device-identity is not valid protobuf") from exc
    if not hmac_wrapper.details or not hmac_wrapper.hmac:
        raise PairingFailed("pair-success device-identity missing details/hmac")

    import hmac as _hmac

    expected = _hmac.new(adv_secret, hmac_wrapper.details, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, hmac_wrapper.hmac):
        raise PairingFailed("pair-success device-identity HMAC did not verify")

    adv = ADVSignedDeviceIdentity()
    try:
        adv.ParseFromString(hmac_wrapper.details)
    except Exception as exc:  # noqa: BLE001
        raise PairingFailed("ADVSignedDeviceIdentity is not valid protobuf") from exc

    device_node = ps.get_child("device")
    if device_node is None:
        raise PairingFailed("pair-success missing device element")
    jid_raw = device_node.get_attr("jid")
    if jid_raw is None:
        raise PairingFailed("pair-success device element missing jid attribute")
    if isinstance(jid_raw, JID):
        jid = jid_raw
    else:
        jid = parse_jid(str(jid_raw))
    return ps, adv, jid, jid.device


# ---------------------------------------------------------------------------
# Pairer
# ---------------------------------------------------------------------------


@dataclass
class PairResult:
    """Outcome of a successful pairing run."""

    device: DeviceStore
    jid: JID
    device_id: int
    # Number of ref rotations the user saw before scanning. Useful for
    # diagnostics; not part of the persisted state.
    refs_emitted: int = 0


# A minimal view of the object the Pairer drives — just enough that
# tests can swap in a fake without pulling in a full NoiseTransport.
class _TransportLike(Protocol):
    async def send(self, plaintext: bytes) -> None: ...
    async def recv(self) -> bytes: ...


@dataclass
class Pairer:
    """Drive the pair-device stanza conversation over a NoiseTransport.

    The transport must already have finished its handshake — the
    registration ``ClientPayload`` goes inside the handshake's leg-3
    payload, not here. This class owns everything that happens after
    the handshake completes up until credentials are safely persisted.
    """

    transport: _TransportLike
    device: DeviceStore
    adv_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    # Clock + sleep hooks so tests can run instantly.
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    # Overall deadline for the pairing attempt.
    total_timeout: float = QR_TOTAL_TIMEOUT_SECONDS
    per_ref_interval: float = QR_REF_INTERVAL_SECONDS
    # WA's web client shows the first QR for 60s before rotating, then
    # every 20s thereafter. Shorter-than-60s initial display has been
    # observed to cause the phone to scan a freshly-rotated ref that
    # the server has already expired.
    first_ref_interval: float = 60.0

    async def run(self, on_qr: QRCallback) -> PairResult:
        """Drive the full pair-device conversation.

        The caller has already run the Noise handshake with a REGISTER
        ClientPayload. We:

        1.  Wait for the server's first iq.
        2.  If it's ``pair-device``, emit QR refs on ``on_qr`` with the
            published rotation cadence until the server pushes a
            ``pair-success`` iq.
        3.  Verify the ADV blob, co-sign it, echo the reply, and fill
            in the DeviceStore fields that were unknown until now.

        On cancellation or error, no partial state is persisted — the
        returned ``PairResult`` is only produced on full success.
        """
        deadline = self.clock() + self.total_timeout
        refs_emitted = 0
        qr_task: asyncio.Task[None] | None = None

        try:
            while True:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    raise PairingFailed("pairing timed out waiting for server")
                try:
                    frame = await asyncio.wait_for(self.transport.recv(), timeout=remaining)
                except TimeoutError as exc:
                    raise PairingFailed("pairing timed out waiting for server") from exc

                node = decode(frame)
                if node.tag == "failure":
                    raise PairingFailed(
                        f"server returned failure stanza: attrs={node.attrs!r} "
                        f"children={[c.tag for c in node.get_children()]}"
                    )
                if node.tag != "iq":
                    _log.debug("ignoring non-iq stanza during pairing: %r", node.tag)
                    continue

                if node.get_child("pair-device") is not None:
                    refs = _extract_pair_device_refs(node)
                    # Acknowledge the iq so the server stops retransmitting.
                    await self._ack_iq(node)
                    # Emit the first QR synchronously so callers see one
                    # even if pair-success arrives immediately after (common
                    # in tests, and harmless in real use).
                    first_payload = encode_qr_payload(
                        refs[0],
                        noise_public=self.device.noise_public,
                        identity_public=self.device.identity_public,
                        adv_secret=self.adv_secret,
                    )
                    try:
                        await on_qr(first_payload)
                    except Exception:  # noqa: BLE001
                        _log.exception("qr handler raised on first emit")
                    if len(refs) > 1:
                        qr_task = asyncio.create_task(
                            self._rotate_qr(refs[1:], on_qr),
                            name="pywhats-pairing-qr",
                        )
                    refs_emitted = len(refs)
                    continue

                # WA sends XMPP-style pings (`<iq type=get xmlns=urn:xmpp:ping>`)
                # every ~30s during pairing. Silent-dropping them kills the
                # session server-side; we must reply with a matching result iq.
                if node.get_str("type") == "get" and node.get_str("xmlns") == "urn:xmpp:ping":
                    await self._ack_iq(node)
                    continue

                if node.get_child("pair-success") is not None:
                    _ps, adv, jid, device_id = _extract_pair_success(
                        node, adv_secret=self.adv_secret
                    )
                    inner = verify_pair_success(
                        adv, our_identity_public=self.device.identity_public
                    )
                    _log.info("pair-success verified (raw_id=%s)", inner.raw_id)
                    reply = build_pair_success_reply(
                        adv,
                        our_identity_private=self.device.identity_private,
                        our_identity_public=self.device.identity_public,
                    )
                    await self._reply_pair_success(node, reply, key_index=inner.key_index)
                    self.device.jid = JIDTuple(user=jid.user, server=jid.server, device=jid.device)
                    self.device.device_id = device_id
                    # Store the FULL identity for later attachment to outbound
                    # messages: reply already has our device_signature; we
                    # re-add account_signature_key (stripped from the echoed
                    # reply) so the stored blob round-trips through WA's
                    # server validator when we embed it in <device-identity>.
                    full_adv = ADVSignedDeviceIdentity()
                    full_adv.CopyFrom(reply)
                    full_adv.account_signature_key = adv.account_signature_key
                    self.device.adv_signed_device_identity = full_adv.SerializeToString()
                    return PairResult(
                        device=self.device,
                        jid=jid,
                        device_id=device_id,
                        refs_emitted=refs_emitted,
                    )

                _log.debug("ignoring unrelated iq during pairing: %r", node.attrs)
        finally:
            if qr_task is not None and not qr_task.done():
                qr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await qr_task

    # ---- helpers -----------------------------------------------------

    async def _rotate_qr(self, refs: list[str], on_qr: QRCallback) -> None:
        """Emit each ref in turn, sleeping ``per_ref_interval`` between.

        We publish the first ref immediately so the user sees a QR as
        soon as possible, then rotate on a fixed cadence. If the server
        sends us only one ref, we simply keep presenting that one until
        pair-success arrives (the consumer is responsible for re-rendering
        on every callback).
        """
        for i, ref in enumerate(refs):
            # Each ref in the sequence is the NEXT one after the
            # currently-displayed QR, so sleep first, then emit.
            # First rotation is 60s after initial QR; later ones 20s.
            interval = self.first_ref_interval if i == 0 else self.per_ref_interval
            await self.sleep(interval)
            payload = encode_qr_payload(
                ref,
                noise_public=self.device.noise_public,
                identity_public=self.device.identity_public,
                adv_secret=self.adv_secret,
            )
            try:
                await on_qr(payload)
            except Exception:  # noqa: BLE001 — consumer errors must not kill pairing
                _log.exception("qr handler raised; continuing rotation")

    async def _ack_iq(self, iq: Node) -> None:
        """Send a minimal ``<iq type="result" .../>`` acknowledgement.

        TODO: Meta's format for the ack is slightly under-documented in
        public writeups; we emit a well-formed stanza with the same
        ``id`` attribute, which is what every writeup agrees on.
        """
        iq_id = iq.get_str("id")
        from_attr = iq.get_attr("from")
        attrs: dict[str, str | int | JID] = {
            "type": "result",
            "id": iq_id or "",
        }
        if from_attr is not None:
            attrs["to"] = from_attr
        ack = Node(tag="iq", attrs=attrs)
        await self.transport.send(encode(ack))

    async def _reply_pair_success(
        self, iq: Node, signed_reply: ADVSignedDeviceIdentity, *, key_index: int
    ) -> None:
        """Send the ``<iq type="result">`` that carries our device-signature."""
        iq_id = iq.get_str("id")
        from_attr = iq.get_attr("from")
        attrs: dict[str, str | int | JID] = {
            "type": "result",
            "id": iq_id or "",
        }
        if from_attr is not None:
            attrs["to"] = from_attr
        pair_device_sign = Node(
            tag="pair-device-sign",
            content=[
                Node(
                    tag="device-identity",
                    attrs={"key-index": str(key_index)},
                    content=signed_reply.SerializeToString(),
                )
            ],
        )
        ack = Node(tag="iq", attrs=attrs, content=[pair_device_sign])
        await self.transport.send(encode(ack))


# ---------------------------------------------------------------------------
# High-level convenience constructors
# ---------------------------------------------------------------------------


def make_fresh_device(*, pairing_name: str = DEFAULT_PAIRING_NAME) -> DeviceStore:
    """Generate all the key material needed to start a pairing attempt."""
    identity = IdentityKeyPair.generate()
    # key_id=1 for the first signed prekey — the server does not care
    # about the numeric value, only that it's stable for the session.
    spk = SignedPreKey.generate(identity, key_id=1)
    noise_priv, noise_pub = generate_keypair()
    # uint32 registration id — 1 .. 2^31-1 is the conventional range used
    # to avoid sign-bit ambiguity with java-style int consumers.
    reg_id = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    if reg_id == 0:
        reg_id = 1
    return DeviceStore.new(
        identity=identity,
        signed_pre_key=spk,
        noise_private=noise_priv,
        noise_public=noise_pub,
        registration_id=reg_id,
        pywhats_version=pairing_name,
    )


__all__ += ["encode_qr_payload", "make_fresh_device"]
