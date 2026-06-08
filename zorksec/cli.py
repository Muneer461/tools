"""ZorkSec command-line entrypoint (the ``tools`` command).

Subcommands implemented in Chunk 1:
  * ``tools init``    - create directories, initialise the DB, provision default user
  * ``tools doctor``  - validate environment, permissions, dependencies, DB integrity
  * ``tools version`` - print version information

Later chunks add ``tools`` (TUI) and ``tools --web`` (dashboard).
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

from zorksec import __app_name__, __author__, __version__
from zorksec.config import ensure_directories, get_settings
from zorksec.db.session import init_db, session_scope
from zorksec.services.auth_service import AuthService
from zorksec.utils.logging import configure_logging, get_logger

logger = get_logger(__name__)

_OK = "[ OK ]"
_WARN = "[WARN]"
_FAIL = "[FAIL]"


def cmd_init(_args: argparse.Namespace) -> int:
    """Initialise directories, database schema, and the default user."""
    settings = get_settings()
    ensure_directories(settings)
    init_db(settings)
    with session_scope(settings) as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
    print(f"{_OK} ZorkSec initialised at {settings.home}")
    print(f"{_OK} Database ready: {settings.db_path}")
    print(f"{_OK} Default login: {settings.default_username} / {settings.default_password} "
          "(you must change this on first login)")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"{__app_name__}")
    print(f"Version : {__version__}")
    print(f"Author  : {__author__}")
    print(f"Python  : {sys.version.split()[0]}")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Run environment / dependency / DB health checks."""
    settings = get_settings()
    problems = 0
    warnings = 0

    print(f"ZorkSec doctor - checking environment\n{'-' * 44}")

    # 1) Python version.
    if sys.version_info >= (3, 10):
        print(f"{_OK} Python {sys.version.split()[0]} (>= 3.10)")
    else:
        print(f"{_FAIL} Python {sys.version.split()[0]} is too old (need >= 3.10)")
        problems += 1

    # 2) Home directory writable.
    try:
        ensure_directories(settings)
        probe = settings.home / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        print(f"{_OK} Home directory writable: {settings.home}")
    except OSError as exc:
        print(f"{_FAIL} Home directory not writable ({settings.home}): {exc}")
        problems += 1

    # 3) Required Python packages.
    required = ["sqlalchemy", "bcrypt", "cryptography"]
    optional = ["flask", "flask_socketio", "gevent", "rich", "psutil", "requests", "distro"]
    for pkg in required:
        if _module_available(pkg):
            print(f"{_OK} Python package '{pkg}' installed")
        else:
            print(f"{_FAIL} Required package '{pkg}' missing")
            problems += 1
    for pkg in optional:
        if _module_available(pkg):
            print(f"{_OK} Python package '{pkg}' installed")
        else:
            print(f"{_WARN} Optional package '{pkg}' missing (needed by later features)")
            warnings += 1

    # 4) Database initialised.
    if settings.db_path.exists():
        try:
            with session_scope(settings) as session:
                from zorksec.repositories.user_repository import UserRepository
                count = UserRepository(session).count()
            print(f"{_OK} Database reachable ({count} user(s) registered)")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"{_FAIL} Database error: {exc}")
            problems += 1
    else:
        print(f"{_WARN} Database not initialised yet - run 'tools init'")
        warnings += 1

    # 5) Master key permissions.
    if settings.key_file.exists():
        mode = oct(os.stat(settings.key_file).st_mode & 0o777)
        if mode == "0o600":
            print(f"{_OK} Master key permissions correct (600)")
        else:
            print(f"{_WARN} Master key permissions are {mode} (expected 600)")
            warnings += 1
    else:
        print(f"{_WARN} Master key not created yet (created on first secret use)")
        warnings += 1

    print(f"{'-' * 44}")
    print(f"Summary: {problems} problem(s), {warnings} warning(s)")
    return 1 if problems else 0


def _module_available(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools",
        description=f"{__app_name__} - command-line interface",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="initialise ZorkSec (dirs, database, default user)")
    sub.add_parser("doctor", help="validate environment, dependencies, and database")
    sub.add_parser("version", help="print version information")

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    dispatch = {
        "init": cmd_init,
        "doctor": cmd_doctor,
        "version": cmd_version,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
