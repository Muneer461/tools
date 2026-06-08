"""System helpers: host facts and safe path resolution.

When ZorkSec runs under ``sudo`` the ``HOME`` environment variable points at
``/root``. Cloning tool repositories there would hide them from the real user,
so :func:`real_home` resolves the invoking user's home via ``SUDO_USER``.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
from pathlib import Path


def real_user() -> str:
    """Return the invoking user (the sudo caller, not root)."""
    return os.environ.get("SUDO_USER") or getpass.getuser()


def real_home() -> Path:
    """Resolve the invoking user's home directory, even under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd  # POSIX only

            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (ImportError, KeyError):
            return Path("/home") / sudo_user
    return Path.home()


def soc_tools_dir() -> Path:
    """Directory where GitHub tool repositories are cloned."""
    return real_home() / "soc_tools" / "github_repos"


def host_facts() -> dict[str, str]:
    """Collect facts shown in the TUI banner (best-effort, never raises)."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = "unknown"
    return {
        "os": _os_label(),
        "kernel": platform.release(),
        "hostname": socket.gethostname(),
        "ip": ip,
        "user": real_user(),
        "python": platform.python_version(),
        "arch": platform.machine(),
    }


def _os_label() -> str:
    try:
        import distro  # type: ignore

        name = distro.name(pretty=True)
        if name:
            return name
    except Exception:
        pass
    return f"{platform.system()} {platform.release()}"
