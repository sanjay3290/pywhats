# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Binary stanza codec for the XMPP-over-binary framing layer."""

from .decoder import decode
from .encoder import encode
from .node import Node

__all__ = ["Node", "encode", "decode"]
