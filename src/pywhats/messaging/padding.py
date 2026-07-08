# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""WhatsApp random message-layer padding (1..16 bytes, all = pad_len).

WhatsApp wraps the serialized ``Message`` protobuf in a one-extra-byte
trailer of *itself* before handing it to Signal: pick a random length
``L`` in ``[1, 16]``, then append ``bytes([L]) * L`` to the proto bytes.
The receiver decrypts via Signal, reads the last byte as ``L``,
verifies all of the trailing ``L`` bytes equal ``L``, and strips them.

Without this padding, the receiver's unpad step interprets the last
byte of the bare protobuf as a pad length and either errors out
(invalid) or strips garbage, then fails to parse a ``Message``. WA
silently drops the result — no retry receipt, no display — which
matches the "server ACK but recipient sees nothing" failure mode.

Reference: Baileys' ``writeRandomPadMax16`` /
``unpadRandomMax16`` in ``src/Utils/generics.ts``. We re-implement
the shape from the public spec; no source copied.
"""

from __future__ import annotations

import os


def pad_random_max16(plaintext: bytes) -> bytes:
    """Append 1..16 trailing bytes whose value equals the pad length."""
    pad_len = (os.urandom(1)[0] & 0x0F) + 1
    return plaintext + bytes([pad_len]) * pad_len


def unpad_random_max16(padded: bytes) -> bytes:
    """Inverse of :func:`pad_random_max16`. Raises ``ValueError`` on bad pad."""
    if not padded:
        raise ValueError("empty padded payload")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16 or pad_len > len(padded):
        raise ValueError(f"invalid pad length {pad_len}")
    if any(b != pad_len for b in padded[-pad_len:]):
        raise ValueError("pad bytes not all equal to pad length")
    return padded[:-pad_len]
