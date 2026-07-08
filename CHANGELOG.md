# Changelog

All notable changes to `pywhats` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-07

The Phase 2 feature release. App-state sync, media, history sync, read
receipts, presence, and group messaging are now implemented, alongside a
round of transport and Signal-store hardening carried over from 0.1.0.
Wire behaviour was captured against real WhatsApp servers before each
piece was built and mirrors whatsmeow/Baileys; the send/receive,
media, receipts, and presence paths were additionally verified live.
The `pywhats.signal.experimental` module remains clean-room and
unaudited (see Security).

### Added

- **App-state sync.** The client stores the keys shared over
  `APP_STATE_SYNC_KEY_SHARE`, fetches and applies `server_sync`
  collection patches (mutation crypto, LTHash integrity, snapshot and
  patch MAC verification), and surfaces individual mutations as events:
  `mute`, `pin`, `archive`, `contact`, and `pushname`. External
  full-sync snapshots are pulled through the media pipeline below.
- **Media send and receive.** `Client.send_image()` encrypts, uploads to
  the WhatsApp CDN, and sends an `ImageMessage`; inbound media is
  downloaded, integrity-checked (enc-file SHA-256, HMAC-SHA-256), and
  decrypted. Keys are derived per the `mediaKey`/HKDF scheme and hosts
  come from a `w:m` media-conn query. Uses stdlib `urllib` in a thread
  by default — no new runtime dependency — with `media_http_get` /
  `media_http_post` seams for injection.
- **History sync.** The four bootstrap `HISTORY_SYNC_NOTIFICATION`
  blobs are downloaded, inflated (zlib), and parsed, emitting a
  `history_sync` event with the sync type, progress, and conversation
  and push-name counts.
- **Read receipts and presence.** `mark_read()`, `send_presence()`,
  `subscribe_presence()`, and `send_chat_presence()` on the client, plus
  `receipt`, `presence`, and `chat_presence` events. Inbound receipts
  are acked to the server, matching whatsmeow.
- **Group messaging.** `get_group_info()` fetches participants over
  `w:g2`; `send_group_text()` distributes a sender-key
  (`SenderKeyDistributionMessage`, fanned out per participant device) and
  sends a sender-key-encrypted group message. Inbound group messages are
  decrypted and emitted as `message` events. The group (sender-key)
  cipher is a new clean-room addition under `pywhats.signal.experimental`
  (see Security).
- **SQLite-backed Signal persistence.** `SqliteStore` consolidates
  sessions, identities, the PN<->LID map, and pre-keys into a single
  `<session>.signal.db`, and is the default store. It gained an
  atomic `transaction()` and tables for app-state keys, app-state
  version and mutation MACs, and group sender keys.
- **LID inbound mapping.** The receiver records PN<->LID pairs from
  inbound stanzas and migrates the peer session to LID so that messages
  addressed over a LID decrypt.
- `Client(ws_url=...)` for pointing the transport at a non-default
  endpoint (used by the in-process fake-server test harness).

### Changed

- One-time prekeys are now uploaded only when the server-side pool drops
  below the low-water mark (queried after each login), instead of a fresh
  50-key batch on every connect.
- One-time prekeys are uploaded over `xmlns=encrypt` and consumed on
  inbound pre-key messages.
- The receiver commits related Signal-store writes (consumed one-time
  prekey, ratchet session, peer identity; PN->LID session migration)
  atomically when running on the SQLite store.
- `_install_messaging` was split into focused helpers
  (`_open_signal_stores`, `_make_responder_identity`, `_own_signal_jid`,
  `_build_activator`).

### Fixed

- **Silent disconnect after ~3 minutes.** The transport's own
  WebSocket-level ping loop fought the WhatsApp edge (the pong returned
  as a data frame, so the waiter never resolved and the connection
  self-closed). WebSocket keepalive is now opt-in and off by default;
  liveness rides on the application-level `w:p` ping, which escalates
  after three consecutive failures, matching whatsmeow.
- The live receiver now replies to server-initiated `<iq type="get">`
  and surfaces a server `<failure>` login rejection as a logged-out
  state instead of hanging.

### Removed

- **Breaking:** the file-based Signal stores (`FileSessionStore`,
  `FileIdentityStore`, `FileLidMap`) and their `.signal/` directory
  layout. `SqliteStore` (a single `<session>.signal.db`) has been the
  client default since it was introduced; clients that still carried a
  stale `.signal/` directory re-establish sessions on next contact.

### Security

- `pywhats.signal.experimental` now also contains the group (sender-key)
  cipher. The module remains clean-room and **unaudited**; it still emits
  a `DeprecationWarning` on import and must not be used for anything that
  matters. See SECURITY.md.

## [0.1.0] - 2026-04-24

First public pre-alpha release. Everything in this version is experimental
and the wire-level behaviour has been reconstructed from public write-ups
rather than verified against real traffic captures. Expect breakage.

### Added

- QR-code device pairing (`Client.connect()` with a fresh session).
- Session resume from disk via `session_path`.
- Sending plain-text messages to individual chats (`Client.send_text`).
- Receiving plain-text messages (the `"message"` event).
- Binary XMPP-style stanza codec (encode/decode).
- Generated protobuf message types under `pywhats.proto`.
- WebSocket transport layer with framing and reconnect primitives.
- Noise-protocol handshake (`XX` pattern) for the initial link-up.
- Experimental Signal double-ratchet support exposed under
  `pywhats.signal.experimental` (opt-in, unaudited).
- Persistent store for identity keys, pre-keys, and session state.
- Event loop: `qr`, `paired`, `connected`, `message`, `decrypt_error`,
  `disconnected`.
- Examples: `examples/pair.py`, `examples/echo.py`,
  `examples/pair_and_echo.py`.

### Known limitations

- The Signal integration lives under `pywhats.signal.experimental`, is
  unaudited, and should not be used for anything that matters.
- The Noise handshake carries three platform-specific TODOs that are
  unverified against a real wire capture; mismatches with production
  servers are possible.
- Pairing stanza shapes and the send/receive stanza shapes are best-guess
  reconstructions from public writeups, not from reverse engineering
  official clients.
- No group chats, no media (images/docs/audio), no read receipts, no
  presence, no app-state sync. Those are planned for 0.2.x and later.
- No retry/resend logic for failed sends beyond what the transport layer
  provides.
- Only Python 3.11+ on CPython is tested.

### Security

- This is a clean-room implementation: no code was copied from official
  clients or from other open-source implementations. Protocol behaviour
  was reconstructed from public writeups (see the README
  acknowledgments).

[0.2.0]: https://github.com/sanjay3290/pywhats/releases/tag/v0.2.0
[0.1.0]: https://github.com/sanjay3290/pywhats/releases/tag/v0.1.0
