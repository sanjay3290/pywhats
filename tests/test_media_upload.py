# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media upload: encrypt + POST + response parse (issue #36 upload).

Mirrors whatsmeow ``upload.go`` (Upload / rawUpload). The encrypt step is
the exact inverse of the download decrypt, so a round-trip through
``decrypt_media`` recovers the plaintext.
"""

from __future__ import annotations

import base64
import json

import pytest

from pywhats.binary import Node
from pywhats.events import JID
from pywhats.media.crypto import MEDIA_IMAGE, decrypt_media
from pywhats.media.upload import (
    MediaUploader,
    UploadResult,
    build_upload_url,
    encrypt_media,
)

_SERVER = JID(user="", server="s.whatsapp.net")


def _media_conn_node(host: str) -> Node:
    mc = Node(
        tag="media_conn",
        attrs={"auth": "AUTH123", "ttl": "3600"},
        content=[Node(tag="host", attrs={"hostname": host})],
    )
    return Node(tag="iq", attrs={"type": "result", "from": _SERVER}, content=[mc])


def test_encrypt_media_round_trips_through_decrypt() -> None:
    plaintext = b"an image payload that spans several AES blocks" * 5
    enc = encrypt_media(plaintext, MEDIA_IMAGE)
    assert enc.file_length == len(plaintext)
    assert len(enc.media_key) == 32
    recovered = decrypt_media(
        enc.enc_data,
        enc.media_key,
        MEDIA_IMAGE,
        file_enc_sha256=enc.file_enc_sha256,
        file_sha256=enc.file_sha256,
    )
    assert recovered == plaintext


def test_build_upload_url() -> None:
    import urllib.parse

    enc_hash = b"\x01\x02\x03\x04"
    token = base64.urlsafe_b64encode(enc_hash).decode()
    url = build_upload_url("mmg.whatsapp.net", "image", enc_hash, "AUTH123")
    assert url.startswith(f"https://mmg.whatsapp.net/mms/image/{token}?")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["auth"] == ["AUTH123"]
    assert query["token"] == [token]


@pytest.mark.asyncio
async def test_uploader_posts_and_parses_response() -> None:
    plaintext = b"hello image bytes"
    posted: list[tuple[str, int]] = []

    async def _send_iq(node: Node) -> Node:
        assert node.get_str("xmlns") == "w:m"
        return _media_conn_node("mmg.whatsapp.net")

    async def _http_post(url: str, body: bytes) -> bytes:
        posted.append((url, len(body)))
        return json.dumps(
            {
                "url": "https://mmg.whatsapp.net/d/full",
                "direct_path": "/v/t62/upload.enc",
                "handle": "HANDLE1",
                "object_id": "OBJ1",
            }
        ).encode()

    up = MediaUploader(send_iq=_send_iq, http_post=_http_post)
    result = await up.upload(plaintext, MEDIA_IMAGE)

    assert isinstance(result, UploadResult)
    assert result.direct_path == "/v/t62/upload.enc"
    assert result.url == "https://mmg.whatsapp.net/d/full"
    assert result.handle == "HANDLE1"
    assert result.file_length == len(plaintext)
    assert len(result.media_key) == 32
    # The POSTed body is the encrypted file (ciphertext + 10-byte mac).
    assert posted and posted[0][1] > len(plaintext)
    # The result's hashes authenticate the plaintext content.
    import hashlib

    assert result.file_sha256 == hashlib.sha256(plaintext).digest()
