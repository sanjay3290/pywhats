# SPDX-License-Identifier: Apache-2.0
"""Signal Protocol namespace for pywhats.

This package intentionally re-exports **nothing** from the experimental
implementation. The Signal Protocol support in this library is UNAUDITED
and lives under ``pywhats.signal.experimental``.

To use it you must opt-in explicitly::

    from pywhats.signal.experimental import (
        IdentityKeyPair, PreKeyBundle, x3dh_initiator, x3dh_responder,
        RatchetState, InMemorySessionStore,
    )

See ``SECURITY.md`` at the repository root for the full list of caveats.
"""

from __future__ import annotations

__all__: list[str] = []
