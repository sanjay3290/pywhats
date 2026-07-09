# SPDX-License-Identifier: Apache-2.0
"""Generated protobuf message classes for the WhatsApp wire protocol.

This package re-exports the key message types so callers can write:

    from pywhats.proto import Message, ClientPayload, HandshakeMessage

See ``proto/`` at the repo root for the hand-authored source schemas,
and ``scripts/gen_proto.sh`` for the regeneration command. Generated
``*_pb2.py`` modules are committed so downstream consumers do not need
a ``protoc`` toolchain.
"""

from .client_payload_pb2 import (
    ClientPayload,
    DevicePairingRegistrationData,
    UserAgent,
    WebInfo,
)
from .companion_reg_pb2 import (
    ADVDeviceIdentity,
    ADVKeyIndexList,
    ADVSignedDeviceIdentity,
    ADVSignedDeviceIdentityHMAC,
    ADVSignedKeyIndexList,
    DeviceProps,
)
from .e2e_pb2 import (
    AppStateSyncKey,
    AudioMessage,
    AppStateSyncKeyData,
    AppStateSyncKeyId,
    AppStateSyncKeyRequest,
    AppStateSyncKeyShare,
    ContextInfo,
    DocumentMessage,
    ExtendedTextMessage,
    HistorySyncNotification,
    ImageMessage,
    Message,
    MessageKey,
    ProtocolMessage,
    SenderKeyDistributionMessage,
    StickerMessage,
    VideoMessage,
)
from .handshake_pb2 import HandshakeMessage
from .history_sync_pb2 import Conversation, HistorySync, HistorySyncMsg, Pushname
from .sender_key_pb2 import SenderKeyDistributionMessageBody, SenderKeyMessageBody
from .server_sync_pb2 import (
    ExitCode,
    ExternalBlobReference,
    KeyId,
    SyncdIndex,
    SyncdMutation,
    SyncdMutations,
    SyncdPatch,
    SyncdRecord,
    SyncdSnapshot,
    SyncdValue,
    SyncdVersion,
)
from .sync_action_pb2 import (
    ArchiveChatAction,
    ContactAction,
    MuteAction,
    PinAction,
    PushNameSetting,
    SyncActionData,
    SyncActionValue,
)
from .whisper_pb2 import PreKeyWhisperMessage, WhisperMessage

__all__ = [
    "ADVDeviceIdentity",
    "ADVKeyIndexList",
    "ADVSignedDeviceIdentity",
    "ADVSignedDeviceIdentityHMAC",
    "ADVSignedKeyIndexList",
    "AppStateSyncKey",
    "AppStateSyncKeyData",
    "AppStateSyncKeyId",
    "AppStateSyncKeyRequest",
    "AppStateSyncKeyShare",
    "ArchiveChatAction",
    "AudioMessage",
    "ClientPayload",
    "ContactAction",
    "ContextInfo",
    "Conversation",
    "DevicePairingRegistrationData",
    "DeviceProps",
    "DocumentMessage",
    "ExitCode",
    "ExtendedTextMessage",
    "ExternalBlobReference",
    "HandshakeMessage",
    "HistorySync",
    "HistorySyncMsg",
    "HistorySyncNotification",
    "ImageMessage",
    "KeyId",
    "Message",
    "MessageKey",
    "MuteAction",
    "PinAction",
    "ProtocolMessage",
    "PreKeyWhisperMessage",
    "Pushname",
    "PushNameSetting",
    "SenderKeyDistributionMessage",
    "SenderKeyDistributionMessageBody",
    "SenderKeyMessageBody",
    "StickerMessage",
    "SyncActionData",
    "SyncActionValue",
    "SyncdIndex",
    "SyncdMutation",
    "SyncdMutations",
    "SyncdPatch",
    "SyncdRecord",
    "SyncdSnapshot",
    "SyncdValue",
    "SyncdVersion",
    "UserAgent",
    "VideoMessage",
    "WebInfo",
    "WhisperMessage",
]
