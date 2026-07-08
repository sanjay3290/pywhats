# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Item 4: one-time prekey upload over xmlns="encrypt" (unit-level shape)."""

from __future__ import annotations

import warnings

warnings.simplefilter("ignore", DeprecationWarning)

from pywhats.binary import decode, encode  # noqa: E402
from pywhats.messaging.prekey import build_prekey_upload_node  # noqa: E402
from pywhats.pairing import make_fresh_device  # noqa: E402
from pywhats.signal.experimental.keys import generate_pre_key  # noqa: E402


def test_build_prekey_upload_node_matches_whatsmeow_shape() -> None:
    device = make_fresh_device()
    opks = [generate_pre_key(i) for i in range(1, 4)]
    node = decode(
        encode(
            build_prekey_upload_node(
                registration_id=device.registration_id,
                identity_public=device.identity_public,
                signed_pre_key=device.signed_pre_key(),
                one_time_pre_keys=opks,
                iq_id="abc123",
            )
        )
    )

    assert node.tag == "iq"
    assert node.get_str("type") == "set"
    assert node.get_str("xmlns") == "encrypt"

    reg = node.get_child("registration")
    assert reg is not None
    assert int.from_bytes(reg.content_bytes(), "big") == device.registration_id

    ktype = node.get_child("type")
    assert ktype is not None and ktype.content_bytes() == b"\x05"

    ident = node.get_child("identity")
    assert ident is not None and len(ident.content_bytes()) == 32

    lst = node.get_child("list")
    assert lst is not None
    key_nodes = lst.get_children("key")
    assert len(key_nodes) == 3
    for opk, kn in zip(opks, key_nodes, strict=True):
        id_child = kn.get_child("id")
        val_child = kn.get_child("value")
        assert id_child is not None and val_child is not None
        assert int.from_bytes(id_child.content_bytes(), "big") == opk.key_id
        assert val_child.content_bytes() == opk.public

    skey = node.get_child("skey")
    assert skey is not None
    assert skey.get_child("signature") is not None
    sid = skey.get_child("id")
    assert sid is not None
    assert int.from_bytes(sid.content_bytes(), "big") == device.signed_pre_key_id
