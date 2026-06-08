"""Central configuration for ZorkSec.

All paths are resolved from ``ZORKSEC_HOME`` (default ``/opt/zorksec``).
Setting the environment variable lets tests and development runs use a
temporary directory instead of the production install location.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _resolve_home() -> Path:
    """Resolve the ZorkSec home directory from the environment."""
    return Path(os.environ.get("ZORKSEC_HOME", "/opt/zorksec")).expanduser()


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings derived from the environment."""

    home: Path = field(default_factory=_resolve_home)

    # Default first-login credentials (must be rotated on first login).
    default_username: str = "zorksec"
    default_password: str = "zorksec"

    # Security policy.
    max_failed_logins: int = 5
    session_timeout_minutes: int = 30
    bcrypt_rounds: int = 12

    # Web server defaults (localhost-only until password is changed).
    web_host: str = "127.0.0.1"
    web_port: int = 8765

    @property
    def db_path(self) -> Path:
        return self.home / "database" / "zorksec.db"

    @property
    def key_file(self) -> Path:
        """Master encryption key file (kept outside the database, mode 0600)."""
        return self.home / "config" / "master.key"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    # Directories that must exist for the platform to operate.
    @property
    def managed_dirs(self) -> list[Path]:
        return [
            self.home,
            self.home / "core",
            self.home / "web",
            self.home / "tui",
            self.home / "plugins",
            self.home / "registry",
            self.home / "database",
            self.home / "reports",
            self.home / "logs",
            self.home / "config",
            self.home / "templates",
            self.home / "static",
        ]


def get_settings() -> Settings:
    """Return a fresh Settings instance (re-reads the environment)."""
    return Settings()


def ensure_directories(settings: Settings | None = None) -> None:
    """Create all managed directories if they do not already exist (idempotent)."""
    settings = settings or get_settings()
    for directory in settings.managed_dirs:
        directory.mkdir(parents=True, exist_ok=True)
