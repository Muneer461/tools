"""Tests for the SecretBox encryption helper."""

from __future__ import annotations

import os
import stat

from zorksec.config import get_settings
from zorksec.security.crypto import SecretBox


def test_encrypt_decrypt_roundtrip(zorksec_home):
    box = SecretBox()
    token = box.encrypt("super-secret-api-key")
    assert token != "super-secret-api-key"
    assert box.decrypt(token) == "super-secret-api-key"


def test_key_file_created_with_0600(zorksec_home):
    SecretBox()  # triggers key creation
    key_file = get_settings().key_file
    assert key_file.exists()
    mode = stat.S_IMODE(os.stat(key_file).st_mode)
    assert mode == 0o600


def test_key_is_reused_across_instances(zorksec_home):
    box1 = SecretBox()
    token = box1.encrypt("hello")
    box2 = SecretBox()  # should load the same key from disk
    assert box2.decrypt(token) == "hello"
