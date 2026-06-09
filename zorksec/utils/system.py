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


def extra_bin_dirs() -> list[Path]:
    """Return common per-user binary directories that tools install into.

    ``go install`` drops binaries in ``$GOPATH/bin`` (default ``~/go/bin``),
    Cargo uses ``~/.cargo/bin``, pip --user uses ``~/.local/bin``, and Go's
    own toolchain may live in ``/usr/local/go/bin``. None of these are
    guaranteed to be on a subprocess PATH, which is why a freshly
    ``go install``-ed tool reports "not found" when run. We add them all.
    """
    import sys

    home = real_home()
    dirs: list[Path] = []

    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.append(Path(gopath) / "bin")
    # The bin/ dir of the running interpreter: where pip console scripts land
    # when ZorkSec installs a pip tool with its own venv python.
    dirs.append(Path(sys.executable).resolve().parent)
    dirs.extend([
        home / "go" / "bin",
        home / ".cargo" / "bin",
        home / ".local" / "bin",
        home / ".local" / "share" / "gem" / "ruby" / "bin",  # ruby gems --user
        Path("/usr/local/go/bin"),
        Path("/usr/local/bin"),
        Path("/snap/bin"),
    ])
    # De-duplicate while preserving order, keeping only existing dirs.
    seen: set[str] = set()
    result: list[Path] = []
    for d in dirs:
        key = str(d)
        if key not in seen and d.is_dir():
            seen.add(key)
            result.append(d)
    return result


def augmented_path() -> str:
    """Return ``$PATH`` with the extra per-user bin dirs prepended."""
    current = os.environ.get("PATH", "")
    extra = os.pathsep.join(str(d) for d in extra_bin_dirs())
    if not extra:
        return current
    return f"{extra}{os.pathsep}{current}" if current else extra


def tool_env() -> dict[str, str]:
    """Return an environment dict with an augmented PATH for running tools."""
    env = dict(os.environ)
    env["PATH"] = augmented_path()
    return env


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



# ---------------------------------------------------------------------------
# OS / distribution detection (used before installing packages)
# ---------------------------------------------------------------------------
# Supported Debian-based security distros and a generic fallback.
SUPPORTED_DISTROS = {"kali", "parrot", "ubuntu", "debian"}


def detect_distro_id() -> str:
    """Return the distro id from /etc/os-release (e.g. 'kali', 'parrot').

    Falls back to the ``distro`` package, then to 'unknown'. Lowercased so
    callers can compare against :data:`SUPPORTED_DISTROS`.
    """
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            data: dict[str, str] = {}
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, _, val = line.partition("=")
                    data[key.strip()] = val.strip().strip('"').lower()
            # ID is the canonical field; ID_LIKE helps for derivatives.
            if data.get("ID"):
                return data["ID"]
            if "kali" in data.get("ID_LIKE", ""):
                return "kali"
        except OSError:
            pass
    try:
        import distro  # type: ignore

        ident = distro.id()
        if ident:
            return ident.lower()
    except Exception:
        pass
    return "unknown"


def is_supported_distro() -> bool:
    """True if the host is a supported Debian-based security distro."""
    return detect_distro_id() in SUPPORTED_DISTROS


def distro_summary() -> dict[str, object]:
    """Return a small dict describing the OS for pre-install checks/UI."""
    distro_id = detect_distro_id()
    return {
        "id": distro_id,
        "label": _os_label(),
        "supported": distro_id in SUPPORTED_DISTROS,
        "uses_apt": Path("/usr/bin/apt-get").exists() or Path("/bin/apt-get").exists(),
    }
