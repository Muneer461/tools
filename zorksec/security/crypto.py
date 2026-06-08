"""Symmetric encryption for secrets (e.g. AI provider API keys).

The master key lives in a file *outside* the database (mode ``0600``). If the
file is missing it is generated on first use. This keeps stored API keys
encrypted at rest rather than merely obfuscated inside the DB.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from zorksec.config import Settings, get_settings


class CryptoError(RuntimeError):
    """Raised when encryption or decryption fails."""


class SecretBox:
    """Loads (or creates) a master key and encrypts/decrypts UTF-8 strings."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        key_file: Path = self._settings.key_file
        if key_file.exists():
            key = key_file.read_bytes().strip()
            if not key:
                raise CryptoError(f"Master key file is empty: {key_file}")
            return key
        # Generate a new key and persist it with restrictive permissions.
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        return key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string, returning a URL-safe token."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by :meth:`encrypt`."""
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:  # pragma: no cover - defensive
            raise CryptoError("Failed to decrypt secret (wrong or rotated key).") from exc
