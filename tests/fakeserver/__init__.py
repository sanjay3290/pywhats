# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Offline fake WhatsApp server test harness.

See :mod:`tests.fakeserver.server` for the scenario documentation.
"""

from __future__ import annotations

from .server import FakeWhatsAppServer, SignalPeer

__all__ = ["FakeWhatsAppServer", "SignalPeer"]
