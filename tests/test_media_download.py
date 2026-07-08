# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media download orchestration: media_conn + URL + downloader (issue #36).

Mirrors whatsmeow ``mediaconn.go`` (queryMediaConn / parse) and
``download.go`` (DownloadMediaWithPath URL construction + host fallback).
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pywhats.binary import Node
from pywhats.events import JID
from pywhats.media.crypto import MEDIA_IMAGE, derive_media_keys
from pywhats.media.download import (
    MediaDownloader,
    MediaInfo,
    build_download_url,
    build_media_conn_iq,
    parse_media_conn,
)

_SERVER = JID(user="", server="s.whatsapp.net")


def _pkcs7(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _encrypt(plaintext: bytes, media_key: bytes, media_type: str) -> tuple[bytes, bytes, bytes]:
    keys = derive_media_keys(media_key, media_type)
    enc = Cipher(algorithms.AES(keys.cipher_key), modes.CBC(keys.iv)).encryptor()
    ciphertext = enc.update(_pkcs7(plaintext)) + enc.finalize()
    mac = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()[:10]
    enc_file = ciphertext + mac
    return enc_file, hashlib.sha256(enc_file).digest(), hashlib.sha256(plaintext).digest()


def _media_conn_node(hosts: list[str]) -> Node:
    children = [Node(tag="host", attrs={"hostname": h}) for h in hosts]
    mc = Node(
        tag="media_conn",
        attrs={"auth": "AUTHTOKEN", "ttl": "3600", "auth_ttl": "21600", "max_buckets": "12"},
        content=children,
    )
    return Node(tag="iq", attrs={"type": "result", "from": _SERVER}, content=[mc])


def test_build_media_conn_iq() -> None:
    node = build_media_conn_iq("iq-1")
    assert node.tag == "iq"
    assert node.get_str("xmlns") == "w:m"
    assert node.get_str("type") == "set"
    assert node.get_child("media_conn") is not None


def test_parse_media_conn() -> None:
    conn = parse_media_conn(_media_conn_node(["mmg.whatsapp.net", "media-fra.whatsapp.net"]))
    assert conn.hosts == ["mmg.whatsapp.net", "media-fra.whatsapp.net"]
    assert conn.auth == "AUTHTOKEN"
    assert conn.ttl == 3600


def test_build_download_url() -> None:
    enc_hash = b"\x01\x02\x03\x04"
    url = build_download_url("mmg.whatsapp.net", "/v/t62.7118-24/x.enc", enc_hash, "image")
    assert url.startswith("https://mmg.whatsapp.net/v/t62.7118-24/x.enc")
    assert "hash=" + base64.urlsafe_b64encode(enc_hash).decode() in url
    assert "mms-type=image" in url
    assert url.endswith("&__wa-mms=")


@pytest.mark.asyncio
async def test_downloader_fetches_and_decrypts() -> None:
    plaintext = b"the quick brown fox jumps over the lazy dog" * 4
    media_key = b"\x33" * 32
    enc_file, enc_sha, sha = _encrypt(plaintext, media_key, MEDIA_IMAGE)

    async def _send_iq(node: Node) -> Node:
        assert node.get_str("xmlns") == "w:m"
        return _media_conn_node(["mmg.whatsapp.net"])

    fetched: list[str] = []

    async def _http_get(url: str) -> bytes:
        fetched.append(url)
        return enc_file

    dl = MediaDownloader(send_iq=_send_iq, http_get=_http_get)
    info = MediaInfo(
        direct_path="/v/t62/x.enc",
        media_key=media_key,
        file_sha256=sha,
        file_enc_sha256=enc_sha,
        media_type=MEDIA_IMAGE,
    )
    out = await dl.download(info)
    assert out == plaintext
    assert fetched and fetched[0].startswith("https://mmg.whatsapp.net/v/t62/x.enc")


@pytest.mark.asyncio
async def test_downloader_falls_back_to_next_host_on_error() -> None:
    plaintext = b"payload that survives a host failover"
    media_key = b"\x44" * 32
    enc_file, enc_sha, sha = _encrypt(plaintext, media_key, MEDIA_IMAGE)

    async def _send_iq(node: Node) -> Node:
        return _media_conn_node(["dead.whatsapp.net", "live.whatsapp.net"])

    async def _http_get(url: str) -> bytes:
        if "dead.whatsapp.net" in url:
            raise OSError("connection refused")
        return enc_file

    dl = MediaDownloader(send_iq=_send_iq, http_get=_http_get)
    info = MediaInfo(
        direct_path="/v/y.enc",
        media_key=media_key,
        file_sha256=sha,
        file_enc_sha256=enc_sha,
        media_type=MEDIA_IMAGE,
    )
    out = await dl.download(info)
    assert out == plaintext


@pytest.mark.asyncio
async def test_download_external_blob_returns_plaintext() -> None:
    # App-state external blobs use the MediaAppState key and download to
    # the raw SyncdSnapshot/SyncdMutations protobuf bytes.
    from pywhats.media.crypto import MEDIA_APP_STATE

    payload = b"\x0a\x10serialized-proto"
    media_key = b"\x55" * 32
    enc_file, enc_sha, sha = _encrypt(payload, media_key, MEDIA_APP_STATE)

    class _Ref:
        media_key = b"\x55" * 32
        direct_path = "/appstate/blob.enc"
        file_sha256 = sha
        file_enc_sha256 = enc_sha

    async def _send_iq(node: Node) -> Node:
        return _media_conn_node(["mmg.whatsapp.net"])

    async def _http_get(url: str) -> bytes:
        return enc_file

    dl = MediaDownloader(send_iq=_send_iq, http_get=_http_get)
    out = await dl.download_external_blob(_Ref())
    assert out == payload
