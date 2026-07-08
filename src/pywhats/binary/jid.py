# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""JID parsing and serialisation helpers.

A "JID" on this protocol is an XMPP-style ``user@server`` address
with two extensions: an optional ``device`` suffix on the user part
(written ``user.device@server`` or sometimes ``user:device@server``
in older writeups) and, for the multi-device "agent/device" form, an
optional ``agent`` qualifier.

The bytes-level encoding is handled in :mod:`pywhats.binary.encoder`
and :mod:`pywhats.binary.decoder`; this module only deals with the
textual / dataclass conversion.

Prose references consulted (no reference-implementation source read):
  * XMPP RFC 6122 for the general ``localpart@domain`` shape.
  * Public XMPP-over-binary writeups describing the per-device
    suffix and the agent/device triple used in multi-device mode.
"""

from __future__ import annotations

from pywhats.events import JID


def parse_jid(text: str) -> JID:
    """Parse a ``user[.device]@server`` string into a :class:`JID`.

    A bare string with no ``@`` is treated as a server-only JID (the
    user component is empty). This matches how some server-routing
    stanzas are sent.
    """
    if "@" not in text:
        return JID(user="", server=text)
    user_part, server = text.split("@", 1)
    device = 0
    # The device suffix may be separated by ``.`` or ``:``.
    for sep in (":", "."):
        if sep in user_part:
            u, d = user_part.rsplit(sep, 1)
            if d.isdigit():
                user_part = u
                device = int(d)
                break
    return JID(user=user_part, server=server, device=device)


def jid_to_str(jid: JID) -> str:
    if not jid.user:
        return jid.server
    if jid.device:
        return f"{jid.user}.{jid.device}@{jid.server}"
    return f"{jid.user}@{jid.server}"


def is_ad_jid(jid: JID) -> bool:
    """Whether a JID should be encoded as the agent/device triple."""
    return jid.device > 0
