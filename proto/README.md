# pywhats protobuf schemas

This directory contains hand-authored `.proto` schemas modelling the
subset of the WhatsApp Web multi-device wire protocol that pywhats
consumes. Field numbers and message shapes are re-derived from public
reverse-engineering writeups of the protocol, not copied from any
particular upstream implementation.

## Files

| File | Messages |
|---|---|
| `handshake.proto` | `HandshakeMessage` (ClientHello / ServerHello / ClientFinish) |
| `client_payload.proto` | `ClientPayload`, `UserAgent`, `WebInfo`, `DevicePairingRegistrationData` |
| `companion_reg.proto` | `DeviceProps`, `ADVDeviceIdentity`, `ADVSignedDeviceIdentity`, `ADVKeyIndexList`, `ADVSignedKeyIndexList`, `ADVSignedDeviceIdentityHMAC` |
| `e2e.proto` | `Message`, `ExtendedTextMessage`, `ContextInfo`, `ProtocolMessage`, `MessageKey`, `SenderKeyDistributionMessage`, app-state sync key messages, `HistorySyncNotification` |

## Clean-room policy

These schemas were **not** copied from any specific upstream source.
In particular:

- **No files were taken from whatsmeow** (Apache-2.0 for schemas, but
  the whole repo is MPL-2.0 for code; to keep a clean licensing story
  we chose not to copy any files from there).
- **No files were taken from Baileys** (MIT) either, despite it being
  license-compatible with Apache-2.0.

Instead, the schemas here were authored from prose descriptions of
the wire format — public protocol documentation, blog posts, and
field-level writeups — with field numbers cross-checked against
public schemas as described below. Message names follow conventional terminology
that is common across *all* independent descriptions of the protocol
(e.g. `HandshakeMessage`, `ClientPayload`, `DeviceProps`,
`ADVSignedDeviceIdentity`) because those names are descriptive of the
observable wire data, not an implementation artifact.

Protobuf field numbers must match the wire protocol exactly or
messages will not decode against real servers. Field numbers are
functional interface facts, not creative expression, so they were
cross-checked against publicly published schemas of open-source
implementations (whatsmeow, Baileys) where the prose writeups were
ambiguous — the schema *text* here (comments, structure, naming of
nested types, subsetting choices) was authored independently. Where
we had low confidence in a number it is marked with a `TODO` comment
in the `.proto` file and should be verified against captured traffic
before the codec is used against the live service.

## Reference material

The following public, non-source-code references were consulted while
authoring these schemas. They describe the WhatsApp Web protocol in
prose and/or tables and are not themselves software licensed under
any copyleft terms that would infect a reimplementation.

- Various public protocol writeups on WhatsApp Web's Noise XX
  handshake and the `ClientPayload` / `HandshakeMessage` envelopes.
- Public blog posts describing the multi-device `ADV*` signed device
  identity flow.
- The protobuf wire format itself
  (<https://protobuf.dev/programming-guides/encoding/>), which
  constrains the space of legal field numbers and types.

No code from any WhatsApp client or server was used.

## Regenerating bindings

```bash
bash scripts/gen_proto.sh
```

This runs `python -m grpc_tools.protoc` against every `.proto` in this
directory and writes `_pb2.py` modules into
`src/pywhats/proto/`. Generated files are committed to the repo so
downstream consumers do not need a `protoc` toolchain.

## Scope

This is the **Phase 1** subset — enough to log in, pair, and send/
receive plain text conversations. Media messages, polls, reactions,
group admin notifications, and app-state syncd mutations are out of
scope here and will be added incrementally. Because protobuf is
forward-compatible, adding new body variants to `Message` or new
fields to any existing message is a non-breaking change.
