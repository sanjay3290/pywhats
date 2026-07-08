# SPDX-License-Identifier: Apache-2.0
"""Minimal QR-pairing example.

Usage::

    python examples/pair.py [session_path]

Opens a WhatsApp Web connection, prints a QR code in the terminal each
time the server rotates the ref, and exits when the user scans the code
with their phone's *Linked Devices* screen. On success the session file
is written to ``session_path`` (default ``./pywhats.session``).

Second and subsequent runs with the same session path skip the QR and
just resume the session.

This script is intentionally runtime-only — not part of the test suite.
It hits the real WhatsApp servers; do not use it in CI.
"""

from __future__ import annotations

import asyncio
import sys

import qrcode

from pywhats import Client

_QR_OPENED = False


def _render_terminal_qr(payload: str) -> None:
    """Render ``payload`` as an ASCII QR to stdout and refresh a PNG."""
    global _QR_OPENED
    qr = qrcode.QRCode(border=2, box_size=10)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    import subprocess

    img = qr.make_image(fill_color="black", back_color="white")
    path = "/tmp/pywhats_qr.png"
    img.save(path)
    if not _QR_OPENED:
        try:
            subprocess.Popen(["open", path])
            _QR_OPENED = True
        except Exception:
            pass
    print(f"(QR refreshed at {path} — scan the CURRENT image)")


async def main(session_path: str) -> int:
    client = Client(session_path=session_path)

    @client.on("qr")
    async def on_qr(payload: str) -> None:
        print("\nScan this with WhatsApp -> Linked Devices -> Link a Device:")
        _render_terminal_qr(payload)

    @client.on("paired")
    async def on_paired(jid: object) -> None:
        print(f"\nPaired as {jid}")

    @client.on("connected")
    async def on_connected() -> None:
        print("Session is live. Press Ctrl-C to exit.")

    try:
        await client.connect()
        await client.wait_closed()
    except KeyboardInterrupt:
        await client.disconnect()
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "pywhats.session"
    raise SystemExit(asyncio.run(main(path)))
