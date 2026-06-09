"""Central configuration for ZorkSec.

All paths are resolved from ``ZORKSEC_HOME`` (default ``/opt/zorksec``).
Setting the environment variable lets tests and development runs use a
temporary directory instead of the production install location.

Secrets (the Flask ``SECRET_KEY``) are resolved from the environment / a
``.env`` file and, failing that, a persistent on-disk key file. They are
*never* regenerated on every restart, so user sessions survive a server
bounce (see :meth:`Settings.resolve_secret_key`).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

# Track which ``.env`` files have already been loaded so repeated
# ``get_settings()`` calls do not re-read the filesystem every time.
_DOTENV_LOADED: set[str] = set()


def _resolve_home() -> Path:
    """Resolve the ZorkSec home directory from the environment."""
    return Path(os.environ.get("ZORKSEC_HOME", "/opt/zorksec")).expanduser()


def _parse_dotenv(path: Path) -> dict[str, str]:
    """Parse a minimal ``.env`` file (``KEY=value`` lines, ``#`` comments).

    Intentionally dependency-free. Values may be quoted; surrounding quotes are
    stripped. Malformed lines are skipped rather than raising.
    """
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def load_dotenv(extra_paths: list[Path] | None = None) -> None:
    """Load ``.env`` files into ``os.environ`` without overriding existing vars.

    Search order (first hit wins per key, and real environment variables always
    take precedence so containers/systemd can override the file):

      1. ``$ZORKSEC_DOTENV`` if set
      2. ``<ZORKSEC_HOME>/.env``
      3. ``./.env`` (current working directory)
    """
    candidates: list[Path] = []
    explicit = os.environ.get("ZORKSEC_DOTENV")
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(_resolve_home() / ".env")
    candidates.append(Path.cwd() / ".env")
    if extra_paths:
        candidates.extend(extra_paths)

    for path in candidates:
        key = str(path)
        if key in _DOTENV_LOADED:
            continue
        _DOTENV_LOADED.add(key)
        if not path.is_file():
            continue
        for env_key, env_value in _parse_dotenv(path).items():
            # Real environment variables win over .env file values.
            os.environ.setdefault(env_key, env_value)


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

    # Password-recovery policy (security-question reset flow).
    max_recovery_attempts: int = 5
    recovery_lockout_minutes: int = 15

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
    def secret_key_file(self) -> Path:
        """Persistent Flask session secret-key file (mode 0600)."""
        return self.home / "config" / "secret.key"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    # ----- secrets / web-origin policy --------------------------------------
    def resolve_secret_key(self) -> str:
        """Return a stable Flask ``SECRET_KEY``.

        Resolution order (a new key is *never* generated on each restart):

          1. ``ZORKSEC_SECRET_KEY`` environment variable (or ``.env``)
          2. a persistent key file under ``config/secret.key`` (mode 0600)
          3. as a last resort, a freshly generated key persisted to that file

        Persisting the key keeps logged-in sessions valid across restarts and
        avoids the previous behaviour of minting a throwaway key every boot.
        """
        env_key = os.environ.get("ZORKSEC_SECRET_KEY")
        if env_key:
            return env_key

        key_path = self.secret_key_file
        try:
            if key_path.exists():
                existing = key_path.read_text(encoding="utf-8").strip()
                if existing:
                    return existing
        except OSError:
            pass

        # Generate once and persist with restrictive permissions.
        generated = secrets.token_hex(32)
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(generated, encoding="utf-8")
            os.chmod(key_path, 0o600)
        except OSError:
            # Read-only filesystem: fall back to an in-memory key for this run.
            pass
        return generated

    def allowed_origins(self) -> list[str]:
        """Return the allow-list of web origins for CORS / Socket.IO.

        Wildcards are deliberately *not* used. ``ZORKSEC_ALLOWED_ORIGINS`` (a
        comma-separated list) extends the defaults, which cover localhost on the
        configured web port plus any common loopback hostnames/ports.

        The port range is generous because the dashboard auto-selects a free
        port when its default is busy; if the bound port were missing here the
        in-browser terminal's WebSocket would be rejected and appear to "hang"
        on "connecting...". ``run_web`` also injects the exact bound origin via
        ``ZORKSEC_ALLOWED_ORIGINS`` as a belt-and-braces guarantee.
        """
        origins: list[str] = []
        hosts = ["127.0.0.1", "localhost", "[::1]"]
        # Common dev/app ports plus the whole 8000-8100 auto-select range used
        # by ``_find_free_port`` so a port switch never breaks the terminal.
        ports = {self.web_port, 8765, 8080, 8000, 5000, 3000}
        ports.update(range(8000, 8101))
        for host in hosts:
            for port in sorted(ports):
                origins.append(f"http://{host}:{port}")
                origins.append(f"https://{host}:{port}")

        configured = os.environ.get("ZORKSEC_ALLOWED_ORIGINS", "")
        for item in configured.split(","):
            item = item.strip().rstrip("/")
            if item and item not in origins:
                origins.append(item)
        return origins

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
    """Return a fresh Settings instance (re-reads the environment).

    Loads ``.env`` files first (without overriding real environment variables)
    so secret-key and origin configuration can live in a file during local use.
    """
    load_dotenv()
    return Settings()


def ensure_directories(settings: Settings | None = None) -> None:
    """Create all managed directories if they do not already exist (idempotent)."""
    settings = settings or get_settings()
    for directory in settings.managed_dirs:
        directory.mkdir(parents=True, exist_ok=True)
