# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Outbound message orchestration.

Public entry points here are the :class:`Sender` (send-side orchestrator)
and :class:`AckRouter` (correlation map for outbound ack / retry
stanzas). The reader task that actually dispatches frames into the
router is deferred to issue #10; this package ships only the sender
half and a mock-friendly router interface.
"""

from .activator import SessionActivator, SuccessState, parse_success
from .ib import IbDispatcher
from .ids import new_message_id
from .receiver import (
    IbHandler,
    PendingIqMap,
    Receiver,
    ResponderIdentityProvider,
    SuccessHandler,
)
from .router import AckRouter, AckRouterProtocol, RetrySignal
from .sender import Sender, SenderConfig
from .usync import UserSyncEntry, USyncDeviceFetcher

__all__ = [
    "AckRouter",
    "AckRouterProtocol",
    "IbDispatcher",
    "IbHandler",
    "PendingIqMap",
    "Receiver",
    "ResponderIdentityProvider",
    "RetrySignal",
    "Sender",
    "SenderConfig",
    "SessionActivator",
    "SuccessHandler",
    "SuccessState",
    "USyncDeviceFetcher",
    "UserSyncEntry",
    "new_message_id",
    "parse_success",
]
