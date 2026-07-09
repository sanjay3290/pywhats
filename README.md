# pywhats

[![CI](https://github.com/sanjay3290/pywhats/actions/workflows/ci.yml/badge.svg)](https://github.com/sanjay3290/pywhats/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pywhats.svg)](https://pypi.org/project/pywhats/)
[![Python versions](https://img.shields.io/pypi/pyversions/pywhats.svg)](https://pypi.org/project/pywhats/)
[![License](https://img.shields.io/pypi/l/pywhats.svg)](https://github.com/sanjay3290/pywhats/blob/main/LICENSE)

Async Python client for the WhatsApp multi-device protocol.

> **Status:** pre-alpha (0.1.0) — the first public release. Implements QR
> pairing, connect, send/receive text, disconnect, app-state sync, media
> (send/receive images), history sync, read receipts, presence, and group
> messaging.

> ⚠️ **Use at your own risk.** This is an independent, unofficial client and
> may violate WhatsApp's Terms of Service — using it can get an account
> banned; prefer a dedicated number. The bundled Signal crypto
> (`pywhats.signal.experimental`) is clean-room and **unaudited** — see
> [SECURITY.md](SECURITY.md).

## Install

```bash
pip install pywhats
```

Requires Python 3.11+.

## Quick start

```python
import asyncio
from pywhats import Client

async def main():
    client = Client()

    @client.on("qr")
    async def on_qr(qr: str):
        print("Scan this QR in WhatsApp → Linked Devices:")
        print(qr)

    @client.on("message")
    async def on_message(msg):
        print(f"{msg.sender}: {msg.text}")
        if msg.text == "ping":
            # Event handlers run on the receive loop, so don't `await` a
            # client call that waits on a server reply (send, receipts,
            # group info) directly here — it would block the loop that has
            # to read that reply. Dispatch it as a task instead.
            asyncio.create_task(client.send_text(msg.chat, "pong"))

    await client.connect()
    await client.wait_closed()

asyncio.run(main())
```

> **Note:** event handlers are dispatched on the connection's receive loop.
> Keep them quick, and never `await` a `Client` call that waits on a server
> response (`send_text`, `send_image`, `mark_read`, `get_group_info`,
> `send_group_text`, …) from inside a handler — schedule it with
> `asyncio.create_task(...)` so the receive loop stays free to read the
> reply.

## Roadmap

- **0.1.0** — QR pair, connect, send/receive text, disconnect, app-state
  sync, media (send/receive images), history sync, read receipts, presence,
  group messaging
- **0.2.0+** — more media types (video/audio/document/sticker), message
  features (reactions/replies/edits), calls, newsletters, business

## License

Apache License 2.0. See [LICENSE](LICENSE).

This is an independent clean-room implementation of the WhatsApp multi-device
protocol. It is not affiliated with or endorsed by WhatsApp LLC or Meta.
Using unofficial clients may violate WhatsApp's Terms of Service and can get
an account banned — use at your own risk, preferably with a dedicated number.

## Acknowledgments

The protocol behavior implemented here was informed by public
reverse-engineering writeups and by studying the documented behavior of the
open-source [whatsmeow](https://github.com/tulir/whatsmeow) (Go) and
[Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript) projects.
No code was copied from either; pywhats is an independent implementation.
