# SPDX-License-Identifier: Apache-2.0
"""libsignal-compatible wire format for Signal message envelopes."""

from __future__ import annotations

import hmac
import warnings
from dataclasses import dataclass
from typing import Final, cast

from pywhats.proto import PreKeyWhisperMessage, WhisperMessage
from pywhats.signal.experimental.keys import SignalCryptoError, signal_pubkey
from pywhats.socket.crypto import hmac_sha256

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)

_MAGIC: Final[int] = 0x33
_MAC_LEN: Final[int] = 8


@dataclass(frozen=True)
class MessageHeader:
    dh: bytes  # sender's current DHs public
    pn: int  # previous chain length
    n: int  # message number

    def encode(self) -> bytes:
        if len(self.dh) != 32:
            raise SignalCryptoError("header dh must be 32 bytes")
        if not (0 <= self.pn < 2**32) or not (0 <= self.n < 2**32):
            raise SignalCryptoError("header counters out of range")
        proto = WhisperMessage()
        proto.ratchetKey = signal_pubkey(self.dh)
        proto.counter = self.n
        proto.previousCounter = self.pn
        return cast(bytes, proto.SerializeToString())

    @classmethod
    def decode(cls, data: bytes) -> tuple[MessageHeader, int]:
        proto = WhisperMessage()
        try:
            proto.ParseFromString(data)
        except Exception as exc:  # noqa: BLE001
            raise SignalCryptoError("invalid whisper message protobuf") from exc
        return (
            cls(
                dh=_strip_signal_pubkey(proto.ratchetKey),
                pn=int(proto.previousCounter),
                n=int(proto.counter),
            ),
            len(data),
        )


@dataclass(frozen=True)
class SignalMessage:
    header: MessageHeader
    ciphertext: bytes
    _body: bytes | None = None
    _mac: bytes | None = None

    def encode(self, sender_identity: bytes, receiver_identity: bytes, mac_key: bytes) -> bytes:
        body = self._body if self._body is not None else self._serialize_body()
        versioned = bytes([_MAGIC]) + body
        return versioned + _mac(sender_identity, receiver_identity, versioned, mac_key)

    @classmethod
    def decode(cls, data: bytes) -> SignalMessage:
        if len(data) < 1 + _MAC_LEN or data[0] != _MAGIC:
            raise SignalCryptoError("bad signal message version")
        body = data[1:-_MAC_LEN]
        mac = data[-_MAC_LEN:]
        proto = WhisperMessage()
        try:
            proto.ParseFromString(body)
        except Exception as exc:  # noqa: BLE001
            raise SignalCryptoError("invalid whisper message protobuf") from exc
        return cls(
            header=MessageHeader(
                dh=_strip_signal_pubkey(proto.ratchetKey),
                pn=int(proto.previousCounter),
                n=int(proto.counter),
            ),
            ciphertext=bytes(proto.ciphertext),
            _body=bytes(body),
            _mac=bytes(mac),
        )

    def verify_mac(self, sender_identity: bytes, receiver_identity: bytes, mac_key: bytes) -> None:
        if self._body is None or self._mac is None:
            # No MAC to check against (message was built in code, not
            # decoded from the wire). Fail closed rather than pass.
            raise SignalCryptoError("signal message has no MAC to verify")
        versioned = bytes([_MAGIC]) + self._body
        expected = _mac(sender_identity, receiver_identity, versioned, mac_key)
        if not hmac.compare_digest(expected, self._mac):
            raise SignalCryptoError("signal message mac check failed")

    def _serialize_body(self) -> bytes:
        proto = WhisperMessage()
        proto.ratchetKey = signal_pubkey(self.header.dh)
        proto.counter = self.header.n
        proto.previousCounter = self.header.pn
        proto.ciphertext = self.ciphertext
        return cast(bytes, proto.SerializeToString())


@dataclass(frozen=True)
class PreKeySignalMessage:
    registration_id: int
    one_time_pre_key_id: int | None
    signed_pre_key_id: int
    base_key: bytes  # EKA public
    identity_key: bytes  # IKA public
    message: SignalMessage

    def encode(self, sender_identity: bytes, receiver_identity: bytes, mac_key: bytes) -> bytes:
        proto = PreKeyWhisperMessage()
        if self.one_time_pre_key_id is not None:
            proto.preKeyId = self.one_time_pre_key_id
        proto.baseKey = signal_pubkey(self.base_key)
        proto.identityKey = signal_pubkey(self.identity_key)
        proto.message = self.message.encode(sender_identity, receiver_identity, mac_key)
        proto.registrationId = self.registration_id
        proto.signedPreKeyId = self.signed_pre_key_id
        return bytes([_MAGIC]) + cast(bytes, proto.SerializeToString())

    @classmethod
    def decode(cls, data: bytes) -> PreKeySignalMessage:
        if len(data) < 1 or data[0] != _MAGIC:
            raise SignalCryptoError("bad prekey signal message version")
        proto = PreKeyWhisperMessage()
        try:
            proto.ParseFromString(data[1:])
        except Exception as exc:  # noqa: BLE001
            raise SignalCryptoError("invalid prekey whisper message protobuf") from exc
        return cls(
            registration_id=int(proto.registrationId),
            one_time_pre_key_id=int(proto.preKeyId) if proto.HasField("preKeyId") else None,
            signed_pre_key_id=int(proto.signedPreKeyId),
            base_key=_strip_signal_pubkey(proto.baseKey),
            identity_key=_strip_signal_pubkey(proto.identityKey),
            message=SignalMessage.decode(bytes(proto.message)),
        )


def _strip_signal_pubkey(public: bytes) -> bytes:
    if len(public) == 33:
        if public[0] != 0x05:
            raise SignalCryptoError("invalid Signal public key type byte")
        return public[1:]
    if len(public) != 32:
        raise SignalCryptoError("invalid Signal public key length")
    return public


def _mac(
    sender_identity: bytes, receiver_identity: bytes, versioned_body: bytes, mac_key: bytes
) -> bytes:
    sender = signal_pubkey(sender_identity)
    receiver = signal_pubkey(receiver_identity)
    return hmac_sha256(mac_key, sender + receiver + versioned_body)[:_MAC_LEN]
