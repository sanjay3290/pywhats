# SPDX-License-Identifier: Apache-2.0
"""Client-version constants exposed during pairing / login.

WhatsApp rejects handshakes whose advertised client version is too old.
These numbers have to be bumped periodically to track the production
web-client. Keeping them in one module means a single-line change to
refresh the whole library.

Values here are drawn from public writeups of the WhatsApp Web protocol
and are intentionally kept conservative. Downstream callers may
override any of them when constructing a :class:`pywhats.Client` once
that plumbing lands.
"""

from __future__ import annotations

# Web-client version tuple advertised inside ``ClientPayload.user_agent``.
# TODO: bump as the upstream web client rolls forward.
WA_WEB_VERSION: tuple[int, int, int] = (2, 3000, 1035194821)

# Display name for pairing — shown to the user on the phone's
# Linked Devices screen. Not an authentication factor.
DEFAULT_PAIRING_NAME: str = "pywhats"

# Identifier persisted in the QR ref rotation and sent as DeviceProps.os.
DEFAULT_DEVICE_OS: str = "pywhats"

# Rotation cadence for the QR refs returned by the server. Public
# writeups report a ~20 s interval; we use this when the server gives
# us more than one ref at a time.
QR_REF_INTERVAL_SECONDS: float = 20.0

# Cap on total time we'll wait for the user to scan before giving up.
# The server typically sends 5 refs; after the last rotation elapses we
# surface a timeout rather than dangling forever.
QR_TOTAL_TIMEOUT_SECONDS: float = 120.0
