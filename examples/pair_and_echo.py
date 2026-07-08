# SPDX-License-Identifier: Apache-2.0
"""Pair with a phone via QR, then echo every incoming text.

Usage::

    python examples/pair_and_echo.py [session_path]

First run prints a QR code; scan it from
*WhatsApp -> Linked Devices -> Link a Device*. Subsequent runs with the
same session path skip the QR and resume. Every inbound text is echoed
back to the sender. Runtime-only — do not run in CI.
"""

from __future__ import annotations

import asyncio
import sys

import qrcode

from pywhats import Client


async def main(session_path: str) -> int:
    client = Client(session_path=session_path)

    @client.on("qr")
    async def on_qr(payload: str) -> None:
        print("\nScan from WhatsApp -> Linked Devices -> Link a Device:")
        qr = qrcode.QRCode(border=1)
        qr.add_data(payload)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    @client.on("paired")
    async def on_paired(jid: object) -> None:
        print(f"Paired as {jid}")

    @client.on("connected")
    async def on_connected() -> None:
        print("Connected. Ctrl-C to quit.")

    @client.on("message")
    async def on_message(msg: object) -> None:
        if getattr(msg, "from_me", False) or not getattr(msg, "text", None):
            return
        await client.send_text(msg.chat, f"echo: {msg.text}")  # type: ignore[attr-defined]

    try:
        await client.connect()
        await client.wait_closed()
    except KeyboardInterrupt:
        await client.disconnect()
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "pywhats.session"
    raise SystemExit(asyncio.run(main(path)))
