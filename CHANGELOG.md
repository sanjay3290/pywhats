# Changelog

All notable changes to `pywhats` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-09

The core message-features batch: the four remaining media types plus
reactions, quoted replies, and edits/revoke. Every outbound variant goes
through the same encrypt/send/ack path as text, so each is fanned out to
the account's own devices wrapped in `DeviceSentMessage`.

### Added

- **Document / video / audio / sticker send + receive.** New
  `Client.send_document`, `send_video`, `send_audio`, and `send_sticker`
  encrypt and upload through the existing media pipeline; inbound media
  surfaces on the `message` event as a new `events.MediaAttachment`
  (duck-types as `MediaInfo`, so `Client.download_media(msg.media)`
  downloads and decrypts it). Voice notes set `send_audio(..., ptt=True)`
  and inbound ptt is exposed on the attachment. Stickers ride the
  `"WhatsApp Image Keys"` HKDF info string and image CDN endpoint (they
  have no media type of their own). New protos `DocumentMessage`,
  `VideoMessage`, `AudioMessage`, `StickerMessage` (whatsmeow waE2E field
  numbers).
- **Reactions.** `Client.send_reaction(chat, message_id, emoji, from_me=)`
  ships a `ReactionMessage` addressing the reacted-to message; an empty
  emoji removes the reaction. Inbound reactions emit a dedicated
  `reaction` event (`events.Reaction`) rather than an empty message.
- **Quoted replies.** `Client.send_text(chat, text, reply_to=Message|
  MessageKey)` wraps the body in an `ExtendedTextMessage` with a
  `ContextInfo` quoting the target. Inbound replies expose the quote on
  `Message.quoted` (`events.QuotedMessage`: stanza id, participant, text).
- **Edits + revoke.** `Client.edit_message(chat, message_id, new_text)`
  and `Client.revoke_message(chat, message_id)` build the matching
  `ProtocolMessage` (`MESSAGE_EDIT` / `REVOKE`) with the correct
  `MessageKey` and the outer `edit` stanza attribute. Inbound edits and
  revokes from a peer surface as `message_edit` / `message_revoke` events
  (`events.MessageEdit` / `MessageRevoke`).

### Notes

- Send-side of documents, audio (ptt), stickers, reactions, edits, and
  revoke is **live-verified** (server-ACKed against the real WhatsApp
  edge on a resumed session). Video send and all inbound directions are
  fakeserver-verified only; full on-device rendering still needs a human
  eyeball. The Signal crypto remains clean-room and **unaudited**.

## [0.1.1] - 2026-07-09

Protocol fixes found while live-testing a companion automation built on
0.1.0.

### Added

- **`DeviceSentMessage` fan-out.** Messages sent from pywhats now appear on
  the account's own phone and other linked devices: the copy fanned out to
  own devices is wrapped in `DeviceSentMessage { destination_jid, message }`
  (new `Message.device_sent_message` field, upstream number 31), which is
  what tells them to render it as outgoing. Applies to every body variant
  and to both retry paths.

### Fixed

- **Terminal `<stream:error>` codes surface as `logged_out`.** Device
  removal or takeover arrives as `<stream:error code="401"><conflict/>`;
  codes `401`/`403` now emit the `logged_out` event, mirroring the
  `<failure>` path, instead of being logged and ignored. The post-pair
  `515` reconnect signal is unaffected.
- **No more tracebacks when app-state sync keys haven't arrived.** On a
  fresh pair, syncing a collection before its `APP_STATE_SYNC_KEY_SHARE`
  lands now logs a single warning and skips the collection; the next
  `server_sync` resumes from the persisted cursor.
- **`status@broadcast` messages no longer spam decrypt errors.** Status
  updates use sender-key encryption the client holds no session for; they
  are now skipped quietly instead of emitting `decrypt_error` events and
  retry receipts.

## [0.1.0] - 2026-07-09

First public release. An async Python client for the WhatsApp multi-device
protocol. Wire behaviour was captured against real WhatsApp servers and
mirrors the documented behaviour of whatsmeow/Baileys; the pairing,
send/receive, media, receipts, and presence paths were additionally verified
live. This is pre-alpha software — expect breakage. The
`pywhats.signal.experimental` module is clean-room and **unaudited** (see
Security).

### Added

- **Device pairing and session.** QR-code pairing (`Client.connect()` with a
  fresh session), login resume from disk via `session_path`, and clean
  disconnect.
- **Text messaging.** Send plain-text messages to individual chats
  (`Client.send_text`) and receive them (the `message` event).
- **Media send and receive.** `Client.send_image()` encrypts, uploads to the
  WhatsApp CDN, and sends an `ImageMessage`; inbound media is downloaded,
  integrity-checked (enc-file SHA-256, HMAC-SHA-256), and decrypted. Keys are
  derived per the `mediaKey`/HKDF scheme; hosts come from a `w:m` media-conn
  query. Uses stdlib `urllib` in a thread by default — no extra runtime
  dependency — with `media_http_get` / `media_http_post` seams for injection.
- **App-state sync.** The client stores keys shared over
  `APP_STATE_SYNC_KEY_SHARE`, fetches and applies `server_sync` collection
  patches (mutation crypto, LTHash integrity, snapshot and patch MAC
  verification), and surfaces mutations as events: `mute`, `pin`, `archive`,
  `contact`, and `pushname`. External full-sync snapshots are pulled through
  the media pipeline.
- **History sync.** The four bootstrap `HISTORY_SYNC_NOTIFICATION` blobs are
  downloaded, inflated (zlib), and parsed, emitting a `history_sync` event
  with the sync type, progress, and conversation and push-name counts.
- **Read receipts and presence.** `mark_read()`, `send_presence()`,
  `subscribe_presence()`, and `send_chat_presence()` on the client, plus
  `receipt`, `presence`, and `chat_presence` events. Inbound receipts are
  acked to the server, matching whatsmeow.
- **Group messaging.** `get_group_info()` fetches participants over `w:g2`;
  `send_group_text()` distributes a sender key
  (`SenderKeyDistributionMessage`, fanned out per participant device) and
  sends a sender-key-encrypted group message. Inbound group messages are
  decrypted and emitted as `message` events.
- **Transport and crypto core.** WebSocket transport with framing and
  reconnect primitives; binary XMPP-style stanza codec; Noise-protocol `XX`
  handshake for link-up; experimental Signal double-ratchet and group
  (sender-key) cipher under `pywhats.signal.experimental` (opt-in, unaudited).
- **SQLite-backed Signal persistence.** `SqliteStore` consolidates sessions,
  identities, the PN<->LID map, and pre-keys into a single
  `<session>.signal.db`, with an atomic `transaction()` and tables for
  app-state keys, app-state version and mutation MACs, and group sender keys.
- **LID inbound mapping.** The receiver records PN<->LID pairs from inbound
  stanzas and migrates the peer session to LID so LID-addressed messages
  decrypt.
- **Liveness.** Application-level `w:p` ping with escalation after three
  consecutive failures (WebSocket keepalive is opt-in and off by default),
  matching whatsmeow.
- Event loop: `qr`, `paired`, `connected`, `message`, `receipt`, `presence`,
  `chat_presence`, `mute`, `pin`, `archive`, `contact`, `pushname`,
  `history_sync`, `decrypt_error`, `disconnected`.
- Examples: `examples/pair.py`, `examples/echo.py`,
  `examples/pair_and_echo.py`.

### Known limitations

- The Signal integration (`pywhats.signal.experimental`) is clean-room,
  unaudited, and must not be used for anything that matters.
- Only Python 3.11+ on CPython is tested.
- No message reactions/replies/edits, no calls, no newsletters, and no media
  types beyond images yet. Those are planned for 0.2.x and later.

### Security

- This is a clean-room implementation: no code was copied from official
  clients or from other open-source implementations. Protocol behaviour was
  reconstructed from public write-ups (see the README acknowledgments). The
  Signal double-ratchet and group (sender-key) cipher in
  `pywhats.signal.experimental` are unaudited; the module emits a
  `DeprecationWarning` on import. See SECURITY.md.

[0.1.1]: https://github.com/sanjay3290/pywhats/releases/tag/v0.1.1
[0.1.0]: https://github.com/sanjay3290/pywhats/releases/tag/v0.1.0
