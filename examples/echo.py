# SPDX-License-Identifier: Apache-2.0
"""Echo-bot example: pair once, then echo every incoming text back.

Usage::

    python examples/echo.py [session_path]

First run pairs with the phone (shows a QR; scan it from
*WhatsApp -> Linked Devices -> Link a Device*). Subsequent runs with
the same session path resume the existing session.

Once connected, every inbound text message is echoed back to the sender
via :meth:`Client.send_text`, exercising both the receive path (#10)
and the send path (#9).

This script is intentionally runtime-only — not part of the test suite.
It hits the real WhatsApp servers; do not use it in CI.
"""

from __future__ import annotations

import asyncio
import sys

import qrcode

from pywhats import Client
from pywhats.events import JID, Message


def _render_terminal_qr(payload: str) -> None:
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


async def main(session_path: str) -> int:
    client = Client(session_path=session_path)

    @client.on("qr")
    async def on_qr(payload: str) -> None:
        print("\nScan this with WhatsApp -> Linked Devices -> Link a Device:")
        _render_terminal_qr(payload)

    @client.on("paired")
    async def on_paired(jid: JID) -> None:
        print(f"\nPaired as {jid}")

    @client.on("connected")
    async def on_connected() -> None:
        print("Session is live. Press Ctrl-C to exit.")

    @client.on("message")
    async def on_message(msg: Message) -> None:
        print(f"[{msg.sender}] {msg.text!r}")
        if msg.from_me or not msg.text:
            return
        reply = f"echo: {msg.text}"
        try:
            await client.send_text(msg.chat, reply)
            print(f"  -> replied to {msg.chat}")
        except Exception as exc:  # noqa: BLE001
            print(f"  !! failed to reply: {exc}")

    @client.on("decrypt_error")
    async def on_decrypt_error(message_id: str, reason: str) -> None:
        print(f"[decrypt_error] id={message_id} reason={reason}")

    @client.on("disconnected")
    async def on_disconnected() -> None:
        print("Disconnected.")

    try:
        await client.connect()
        await client.wait_closed()
    except KeyboardInterrupt:
        await client.disconnect()
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "pywhats.session"
    raise SystemExit(asyncio.run(main(path)))
