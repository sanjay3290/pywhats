# SPDX-License-Identifier: Apache-2.0
"""pywhats experimental Signal Protocol implementation.

WARNING: This module is UNAUDITED and should not be used for production
end-to-end encryption until reviewed by a cryptographer. See ``SECURITY.md``
at the repository root.

The public API exported here is intentionally small.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "pywhats.signal.experimental is UNAUDITED. Do not use for production E2E. See SECURITY.md.",
    DeprecationWarning,
    stacklevel=2,
)

from pywhats.signal.experimental.identity_store import (  # noqa: E402
    IdentityStore,
    InMemoryIdentityStore,
)
from pywhats.signal.experimental.keys import (  # noqa: E402
    IdentityKeyPair,
    PreKeyBundle,
    SignedPreKey,
    generate_pre_key,
    xeddsa_sign,
    xeddsa_verify,
)
from pywhats.signal.experimental.lid_map import (  # noqa: E402
    InMemoryLidMap,
    LidMap,
)
from pywhats.signal.experimental.prekey_store import (  # noqa: E402
    InMemoryPreKeyStore,
    PreKeyStore,
)
from pywhats.signal.experimental.ratchet import (  # noqa: E402
    DEFAULT_MAX_SKIP,
    RatchetState,
    ratchet_decrypt,
    ratchet_encrypt,
    ratchet_init_alice,
    ratchet_init_bob,
)
from pywhats.signal.experimental.sqlite_store import (  # noqa: E402
    SqliteIdentityStore,
    SqliteLidMap,
    SqlitePreKeyStore,
    SqliteSessionStore,
    SqliteStore,
)
from pywhats.signal.experimental.store import (  # noqa: E402
    InMemorySessionStore,
    SessionStore,
)
from pywhats.signal.experimental.types import (  # noqa: E402
    PreKeySignalMessage,
    SignalMessage,
)
from pywhats.signal.experimental.x3dh import (  # noqa: E402
    X3DH_INFO,
    x3dh_initiator,
    x3dh_responder,
)

__all__ = [
    "DEFAULT_MAX_SKIP",
    "IdentityKeyPair",
    "IdentityStore",
    "InMemoryLidMap",
    "InMemoryIdentityStore",
    "InMemoryPreKeyStore",
    "InMemorySessionStore",
    "LidMap",
    "PreKeyBundle",
    "PreKeySignalMessage",
    "PreKeyStore",
    "RatchetState",
    "SessionStore",
    "SignalMessage",
    "SignedPreKey",
    "SqliteIdentityStore",
    "SqliteLidMap",
    "SqlitePreKeyStore",
    "SqliteSessionStore",
    "SqliteStore",
    "X3DH_INFO",
    "generate_pre_key",
    "ratchet_decrypt",
    "ratchet_encrypt",
    "ratchet_init_alice",
    "ratchet_init_bob",
    "x3dh_initiator",
    "x3dh_responder",
    "xeddsa_sign",
    "xeddsa_verify",
]
