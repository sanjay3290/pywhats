# Security

## Status: EXPERIMENTAL / UNAUDITED

The Signal Protocol implementation in `pywhats.signal.experimental` is a
clean-room Python implementation written from the public Signal specifications
alone (X3DH, Double Ratchet, XEdDSA). It has **not** been reviewed by a
cryptographer and **must not** be used to protect any production end-to-end
encrypted traffic until it has been.

Concrete reasons for caution:

- The Ed25519 scalar / point arithmetic used by XEdDSA
  (`src/pywhats/signal/experimental/_ed25519.py`) is a small pure-Python
  reference implementation. It is **not constant time** and likely leaks
  secret-scalar bits through timing. This is unsuitable for any adversarial
  environment.
- There are no cross-implementation byte-level test vectors. Tests in this
  repo prove self-consistency (Alice talking to Bob with this same library),
  not conformance with the Signal wire protocol or interoperability with any
  other Signal implementation.
- Memory hygiene in CPython is best-effort. We zeroise `bytearray` key
  material where feasible, but garbage-collected `bytes` objects may linger.
- The `SqliteStore` persists ratchet keys and peer identities on disk in
  the clear. Disk encryption is the caller's responsibility.

## Non-goals

- Interoperability with the official Signal / WhatsApp wire format. The
  wire framing in `types.py` is a minimal in-repo format, not the format
  any external Signal-compatible peer expects.
- Resistance to side-channel attacks (timing, cache, EM, etc.).

## Implementation choices made

The Signal specifications intentionally leave some parameters
application-defined. Every such choice made by this implementation is
listed here. If any of these choices is wrong for your use case, you must
change it before depending on this code.

1. **Curve**: X25519. (X3DH / Double Ratchet support X448; we do not.)
2. **Hash**: SHA-256 for HKDF and HMAC throughout X3DH and the Double Ratchet.
3. **X3DH `F` prefix**: 32 bytes of `0xFF` (mandated by X3DH 2.1 for X25519).
4. **X3DH KDF salt**: 32 zero bytes (HKDF hash output length; mandated by
   X3DH 2.2).
5. **X3DH `info` string**: the ASCII bytes
   `pywhats.signal.experimental X3DH v1`. Any peer you talk to must use the
   same string.
6. **X3DH associated data**: `AD = IKA_pub || IKB_pub`, each encoded as the
   raw 32-byte X25519 public key (`Encode` per X3DH 2.5 for X25519). No
   certificates or usernames are appended.
7. **Double Ratchet AEAD**: AES-256-CBC + HMAC-SHA-256, following the scheme
   recommended in Double Ratchet 5.2 (HKDF expands `mk` to 80 bytes →
   32-byte encryption key, 32-byte auth key, 16-byte IV; HMAC covers
   `AD || ciphertext`). We did **not** use AES-GCM.
8. **Double Ratchet KDF_CK constants**: `0x01` for the message key,
   `0x02` for the next chain key (mandated by Double Ratchet 5.2).
9. **Double Ratchet KDF_RK info string**:
   `pywhats.signal.experimental DR RK v1`.
10. **Double Ratchet ENCRYPT info string**:
    `pywhats.signal.experimental DR MK v1`.
11. **Double Ratchet HKDF salt for ENCRYPT**: 32 zero bytes (Double
    Ratchet 5.2).
12. **Header encryption**: NOT implemented. The ratchet uses the baseline
    (unencrypted header) variant described in Double Ratchet sections 3–4.
    If you need the header-encryption variant of the spec, this library is
    not for you.
13. **`MAX_SKIP` per chain**: 1000 by default
    (`ratchet.DEFAULT_MAX_SKIP`). Configurable per-session via
    `RatchetState.max_skip`.
14. **Total skipped-key cache bound**: 2000 entries across all chains,
    beyond which the oldest entries are evicted FIFO. This is a defence
    against memory exhaustion and is **not** specified by Signal.
15. **Ratchet advance ordering in decrypt**: (a) try skipped keys; (b) if
    `header.dh` differs from `state.dhr`, skip up to `header.pn` in the
    current receiving chain then perform a DH ratchet step; (c) skip up
    to `header.n` in the new receiving chain; (d) derive the message key.
    This follows the pseudocode in Double Ratchet 3.4 / 3.5.
16. **RatchetInitBob DH key**: Bob reuses his signed prekey (SPKB) as the
    initial `DHs`. This matches the X3DH → Double Ratchet handover implied
    by the specs (the first DH Alice performs is against SPKB).
17. **XEdDSA hash**: SHA-512 (XEdDSA 2.2).
18. **XEdDSA `hash1` prefix for Curve25519**: `0xFE` followed by 31 `0xFF`
    bytes (XEdDSA 2.2).
19. **XEdDSA nonce `Z`**: 64 random bytes from `secrets.token_bytes`.
20. **Wire format**: a local binary framing (`types.SignalMessage`,
    `types.PreKeySignalMessage`) — **not** the WhatsApp / Signal wire
    format. Do not expect interop.
21. **Session-store serialisation**: JSON with base64-encoded keys, schema
    version 1. Files are written atomically (temp file + `os.replace`)
    with mode `0600` on POSIX.

## How to verify

- Run the test suite:
  `.venv/bin/pytest tests/test_signal_ratchet.py tests/test_signal_store.py`.
- Read the code starting at `src/pywhats/signal/experimental/__init__.py`.
  Every module carries spec references in comments at the meaningful steps
  (e.g. `# X3DH 3.2 step 2`, `# Double Ratchet 3.5 DHRatchet`).
- The code is small (roughly 2k lines plus tests). A crypto engineer
  should be able to audit it in a day.

## Reporting issues

Open a GitHub issue on `sanjay3290/pywhats` for non-security bugs. For
suspected security vulnerabilities, please open a private security advisory
via GitHub (*Security → Report a vulnerability* on the repo). Do **not**
file a public issue for a vulnerability in the cryptographic code.
