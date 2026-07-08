# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Known-answer tests for app-state mutation crypto (issue #35b).

The expected values were produced by a stdlib-only reference script
(RFC 5869 HKDF-SHA256 + pointwise uint16-LE arithmetic), independent of
the ``cryptography``-lib implementation under test. Each parameter is
pinned to a whatsmeow source location so a wire-behaviour drift is
caught here rather than live.
"""

from __future__ import annotations

from pywhats.appstate.crypto import (
    ExpandedAppStateKeys,
    aes_cbc_decrypt,
    expand_app_state_keys,
    generate_content_mac,
)
from pywhats.appstate.lthash import subtract_then_add

# --- key expansion (whatsmeow appstate/keys.go expandAppStateKeys) ----

_KEY_DATA = bytes(range(32))


def test_expand_app_state_keys_splits_160_bytes_into_five() -> None:
    keys = expand_app_state_keys(_KEY_DATA)
    assert isinstance(keys, ExpandedAppStateKeys)
    assert keys.index.hex() == "61387bcf643616a68bd611a45516b3980418323087d78bf08c615645549434b4"
    assert (
        keys.value_encryption.hex()
        == "900ba2843ba5fb0cee55cf2a4de9503dce68187d3f6b95b420b008bde66f5a20"
    )
    assert (
        keys.value_mac.hex() == "d0879f6b61f0bcba79faad3f47a8a768fd7fc04a6cc8b3ecefedfa087413226f"
    )
    assert (
        keys.snapshot_mac.hex()
        == "69b2e91be6587307c43c29b027a71fdd55be25f07ca726714115430d23093071"
    )
    assert (
        keys.patch_mac.hex() == "693845bdd996652aca9ca0b96d0f081abf29943303c5eb19bdb84f38b24c32ab"
    )


def test_expand_app_state_keys_each_subkey_is_32_bytes() -> None:
    keys = expand_app_state_keys(_KEY_DATA)
    for sub in (
        keys.index,
        keys.value_encryption,
        keys.value_mac,
        keys.snapshot_mac,
        keys.patch_mac,
    ):
        assert len(sub) == 32


# --- LT-hash (whatsmeow appstate/lthash) ------------------------------

_ZERO = b"\x00" * 128


def test_lthash_add_single_item_matches_reference() -> None:
    got = subtract_then_add(_ZERO, added=[b"item-one"], removed=[])
    assert got.hex().startswith("389d57c7c4ba4136825c23e128f81a28")
    assert len(got) == 128


def test_lthash_is_commutative_add_then_subtract() -> None:
    both = subtract_then_add(_ZERO, added=[b"item-one", b"item-two"], removed=[])
    # Removing item-one from {one, two} equals adding item-two alone.
    minus_one = subtract_then_add(both, added=[], removed=[b"item-one"])
    two_only = subtract_then_add(_ZERO, added=[b"item-two"], removed=[])
    assert minus_one == two_only


def test_lthash_add_then_remove_same_item_returns_to_base() -> None:
    added = subtract_then_add(_ZERO, added=[b"x"], removed=[])
    back = subtract_then_add(added, added=[], removed=[b"x"])
    assert back == _ZERO


def test_lthash_does_not_mutate_input() -> None:
    base = bytearray(_ZERO)
    subtract_then_add(bytes(base), added=[b"y"], removed=[])
    assert bytes(base) == _ZERO


# --- content MAC (whatsmeow appstate/hash.go generateContentMAC) ------


def test_content_mac_set_matches_reference() -> None:
    mac = generate_content_mac(
        operation=0, data=b"hello world", key_id=b"\x01\x02\x03", value_mac_key=b"K" * 32
    )
    assert mac.hex() == "07ac49d312decab80f9fbdf95cc54af0997c628727c1befa36e94c64ca53bf91"


def test_content_mac_remove_differs_from_set() -> None:
    # The operation byte (operation+1) is the first HMAC input, so SET
    # and REMOVE over identical data must differ.
    mac = generate_content_mac(
        operation=1, data=b"hello world", key_id=b"\x01\x02\x03", value_mac_key=b"K" * 32
    )
    assert mac.hex() == "7f29d8fe14c7c25076f715254fed1eef41ebec60b834d9c5f3b9867cb0c82c78"


# --- AES-CBC decrypt (whatsmeow decode.go, cbcutil) -------------------


def test_aes_cbc_decrypt_roundtrips_iv_prefixed_ciphertext() -> None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"E" * 32
    iv = b"I" * 16
    plaintext = b"a mutation payload of arbitrary length"
    # WhatsApp value blobs are PKCS#7-padded (whatsmeow cbcutil.Encrypt);
    # aes_cbc_decrypt strips that padding.
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    got = aes_cbc_decrypt(key, iv + ct)
    assert got == plaintext
