"""Event payload dataclasses emitted by Client."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class JID:
    user: str
    server: str = "s.whatsapp.net"
    device: int = 0

    def __str__(self) -> str:
        if self.device:
            return f"{self.user}.{self.device}@{self.server}"
        return f"{self.user}@{self.server}"


@dataclass(slots=True)
class MediaAttachment:
    """A downloadable attachment referenced by a message (0.2.0 media).

    Carries everything :meth:`pywhats.client.Client.download_media`
    needs (it duck-types as :class:`pywhats.media.download.MediaInfo`):
    the CDN ``direct_path``, the 32-byte ``media_key``, the two
    integrity hashes, and ``media_type`` (the HKDF info string, e.g.
    ``"WhatsApp Document Keys"``). ``kind`` names the message variant
    (``"document"``, ...) since sticker and image share a media_type.
    """

    kind: str
    direct_path: str
    media_key: bytes
    file_sha256: bytes
    file_enc_sha256: bytes
    media_type: str
    file_length: int
    mimetype: str = ""
    filename: str = ""
    caption: str = ""
    # Voice note (push-to-talk) flag; only meaningful for kind="audio".
    ptt: bool = False
    # Required by the downloader protocol; empty means "derive from
    # media_type" (see MediaDownloader.download).
    mms_type: str = ""


@dataclass(slots=True)
class Message:
    id: str
    chat: JID
    sender: JID
    text: str
    timestamp: int
    from_me: bool = False
    # Set when the message carries a downloadable attachment.
    media: MediaAttachment | None = None


@dataclass(slots=True)
class Reaction:
    """An emoji reaction to an existing message (0.2.0).

    ``message_id`` + ``key_from_me`` are the reacted-to message's raw
    MessageKey coordinates as sent by the reactor (``key_from_me`` is
    from *their* perspective). ``text`` is the emoji; ``""`` means the
    reaction was removed. ``timestamp`` is the sender timestamp in ms.
    """

    chat: JID
    sender: JID
    message_id: str
    text: str
    key_from_me: bool
    timestamp: int


# --- app-state events (issue #35d) -----------------------------------
#
# Decoded app-state mutations surfaced as typed events. ``timestamp`` is
# the action timestamp in milliseconds (whatsmeow ``mutation.Action
# .GetTimestamp()``). Mirrors whatsmeow ``events.Mute`` / ``Pin`` /
# ``Archive`` / ``Contact`` / ``PushNameSetting``.


@dataclass(slots=True)
class Contact:
    """A contact's name was set/updated in the address book."""

    jid: JID
    first_name: str
    full_name: str
    timestamp: int


@dataclass(slots=True)
class PushName:
    """The user's own push name (display name) setting changed."""

    name: str
    timestamp: int


@dataclass(slots=True)
class Mute:
    """A chat was muted or unmuted."""

    jid: JID
    muted: bool
    mute_end_timestamp: int
    timestamp: int


@dataclass(slots=True)
class Pin:
    """A chat was pinned or unpinned."""

    jid: JID
    pinned: bool
    timestamp: int


@dataclass(slots=True)
class Archive:
    """A chat was archived or unarchived."""

    jid: JID
    archived: bool
    timestamp: int


# --- receipts + presence (issue #38) ---------------------------------


@dataclass(slots=True)
class Receipt:
    """A delivery/read receipt for one or more of our sent messages.

    ``type`` is the wire receipt type — ``""`` for a plain delivery
    receipt (two grey ticks), ``"read"`` (blue ticks), ``"read-self"``,
    ``"played"``, etc. (whatsmeow ``events.Receipt``). ``message_ids`` is
    the primary id plus any carried in the ``<list>``.
    """

    from_jid: JID
    message_ids: list[str]
    type: str
    timestamp: int
    participant: JID | None = None


@dataclass(slots=True)
class Presence:
    """A peer's online/offline presence update (whatsmeow ``events.Presence``)."""

    from_jid: JID
    unavailable: bool
    last_seen: int | None = None


@dataclass(slots=True)
class ChatPresence:
    """A peer's typing/recording state in a chat (whatsmeow ``events.ChatPresence``)."""

    from_jid: JID
    state: str  # "composing" | "paused"
    media: str = ""  # "" | "audio"


# --- history sync (issue #37) ----------------------------------------


# --- groups (issue #39) ----------------------------------------------


@dataclass(slots=True)
class GroupParticipant:
    """One member of a group and their admin rank."""

    jid: JID
    is_admin: bool = False
    is_super_admin: bool = False


@dataclass(slots=True)
class GroupInfo:
    """Group metadata from a ``w:g2`` query (whatsmeow ``types.GroupInfo``)."""

    jid: JID
    subject: str
    owner: JID | None
    participants: list[GroupParticipant]
    announce: bool = False
    locked: bool = False


@dataclass(slots=True)
class HistorySync:
    """A decoded HISTORY_SYNC_NOTIFICATION chunk (whatsmeow ``events.HistorySync``).

    Carries a summary of the downloaded + inflated ``HistorySync`` blob:
    the sync type, progress, and the conversations / push names it
    delivered. Field-level chat history (per-message ``WebMessageInfo``)
    is left opaque for now.
    """

    sync_type: str
    progress: int
    chunk_order: int
    conversation_count: int
    message_count: int
    conversation_ids: list[str]
    pushnames: list[tuple[str, str]]
