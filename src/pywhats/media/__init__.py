# Copyright 2026 Sanjay Ramadugu
# SPDX-License-Identifier: Apache-2.0
"""Media (attachment) transfer — download + upload (issue #36).

Download derives AES/HMAC keys from a message's 32-byte ``mediaKey`` and
verifies + decrypts a CDN blob (:mod:`pywhats.media.crypto`); the
:class:`~pywhats.media.download.MediaDownloader` fetches the media CDN
host list and performs the HTTP GET.
"""

from .crypto import (
    MEDIA_APP_STATE,
    MEDIA_AUDIO,
    MEDIA_DOCUMENT,
    MEDIA_HISTORY,
    MEDIA_IMAGE,
    MEDIA_VIDEO,
    MediaError,
    decrypt_media,
    derive_media_keys,
)
from .download import MediaDownloader, MediaInfo, default_http_get
from .upload import MediaUploader, UploadResult, default_http_post, encrypt_media

__all__ = [
    "MEDIA_IMAGE",
    "MEDIA_VIDEO",
    "MEDIA_AUDIO",
    "MEDIA_DOCUMENT",
    "MEDIA_HISTORY",
    "MEDIA_APP_STATE",
    "MediaError",
    "MediaDownloader",
    "MediaInfo",
    "MediaUploader",
    "UploadResult",
    "decrypt_media",
    "derive_media_keys",
    "encrypt_media",
    "default_http_get",
    "default_http_post",
]
