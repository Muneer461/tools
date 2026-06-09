"""ZorkSec command-line entrypoint (the ``zorksec`` command).

Subcommands implemented in Chunk 1:
  * ``zorksec init``    - create directories, initialise the DB, provision default user
  * ``zorksec doctor``  - validate environment, permissions, dependencies, DB integrity
  * ``zorksec version`` - print version information

Later chunks add ``zorksec`` (TUI) and ``zorksec --web`` (dashboard).
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
from zorksec.services.dependency_service import DependencyService
from zorksec.services.discovery_service import DiscoveryService
from zorksec.services.registry_service import RegistryService
from zorksec.utils.logging import configure_logging, get_logger

logger = get_logger(__name__)

_OK = "[ OK ]"
_WARN = "[WARN]"
_FAIL = "[FAIL]"


def cmd_init(_args: argparse.Namespace) -> int:
    """Initialise directories, database schema, default user, and catalog."""
    settings = get_settings()
    ensure_directories(settings)
    init_db(settings)
    with session_scope(settings) as session:
        AuthService(session, settings).ensure_default_user()
        count = RegistryService(session).seed_catalog()
    with session_scope(settings) as session:
        installed = DiscoveryService(session).sync_installed_status()
    with session_scope(settings) as session:
        from zorksec.services.ti_service import ThreatIntelService
        ThreatIntelService(session).seed_sample_feed()
    print(f"{_OK} ZorkSec initialised at {settings.home}")
    print(f"{_OK} Database ready: {settings.db_path}")
    print(f"{_OK} Catalog seeded: {count} tools ({installed} already installed on this host)")
    print(f"{_OK} Default login: {settings.default_username} / {settings.default_password} "
          "(you must change this on first login)")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    """List the tool catalog for a team profile, grouped by category."""
    team = getattr(args, "team", "both") or "both"
    with session_scope() as session:
        svc = RegistryService(session)
        if svc.tools.count() == 0:
            svc.seed_catalog()
        tools = svc.list_for_team(team)
        by_cat: dict[str, list] = {}
        for tool in tools:
            by_cat.setdefault(tool.category, []).append(tool)
        print(f"ZorkSec catalog - profile '{team}' ({len(tools)} tools)\n{'-' * 44}")
        for category, items in by_cat.items():
            print(f"\n[{category}]")
            for tool in items:
                mark = "*" if (tool.status and tool.status.installed) else " "
                print(f"  [{mark}] {tool.name} ({tool.slug}) - {tool.team}")
    return 0


def cmd_discover(_args: argparse.Namespace) -> int:
    """Detect which catalog tools are already installed on this host."""
    with session_scope() as session:
        svc = RegistryService(session)
        if svc.tools.count() == 0:
            svc.seed_catalog()
        installed = DiscoveryService(session).sync_installed_status()
    print(f"{_OK} Discovery complete: {installed} catalog tool(s) detected as installed")
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the interactive terminal UI."""
    try:
        from zorksec.tui.app import launch
    except ImportError as exc:
        print(f"{_FAIL} TUI unavailable (is 'rich' installed?): {exc}")
        return 1
    team = getattr(args, "team", "both") or "both"
    return launch(team=team)


def cmd_web(args: argparse.Namespace) -> int:
    """Launch the Flask + SocketIO web dashboard."""
    try:
        from zorksec.web.app import run_web
    except ImportError as exc:
        print(f"{_FAIL} Web dashboard unavailable (install flask, flask-socketio, gevent): {exc}")
        return 1
    return run_web(host=getattr(args, "host", None), port=getattr(args, "port", None))


def cmd_deps(_args: argparse.Namespace) -> int:
    """Show build/runtime dependency status (Python, Docker, Go, etc.)."""
    print(f"ZorkSec dependency engine\n{'-' * 44}")
    for dep in DependencyService().detect():
        if dep.present:
            ver = f" {dep.version}" if dep.version else ""
            print(f"{_OK} {dep.name}{ver}")
        else:
            print(f"{_WARN} {dep.name} missing  -> {dep.install_hint}")
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Run the Diagnostic Center checks from the command line."""
    from zorksec.services.diagnostic_service import DiagnosticService
    svc = DiagnosticService()
    report = svc.run_full_diagnostic()
    print(f"ZorkSec Diagnostic Center - overall: {report.overall.upper()}\n{'-' * 44}")
    mark = {"ok": _OK, "warning": _WARN, "fail": _FAIL, "unknown": _WARN}
    for check in report.checks:
        print(f"{mark.get(check.status, _WARN)} {check.name}: {check.detail}")
    if getattr(args, "repair", False):
        print(f"{'-' * 44}\nAuto-repair:")
        for result in svc.auto_repair():
            state = "fixed" if result.success else ("failed" if result.attempted else "skipped")
            print(f"  [{state}] {result.key}: {result.detail}")
    print(f"{'-' * 44}\nRoot cause analysis:")
    for line in svc.root_cause_analysis(report):
        print(f"  - {line}")
    return 1 if report.overall == "fail" else 0


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
        print(f"{_WARN} Database not initialised yet - run 'zorksec init'")
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


def cmd_attack(_args: argparse.Namespace) -> int:
    """Show ATT&CK tactic coverage based on the seeded tool mappings."""
    from zorksec.services.attack_service import AttackService
    with session_scope() as session:
        from zorksec.services.registry_service import RegistryService
        if RegistryService(session).tools.count() == 0:
            RegistryService(session).seed_catalog()
        coverage = AttackService(session).coverage_by_tactic()
    print(f"MITRE ATT&CK tactic coverage\n{'-' * 44}")
    for tac in coverage:
        bar = "#" * tac.covered_count + "-" * max(0, tac.technique_count - tac.covered_count)
        print(f"{tac.tactic:<24} [{bar}] {tac.covered_count}/{tac.technique_count}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a report and export it to a file."""
    from zorksec.services.report_service import ReportService
    rtype = getattr(args, "type", "incident")
    title = getattr(args, "title", None) or f"{rtype.title()} Report"
    fmt = getattr(args, "format", "markdown")
    with session_scope() as session:
        svc = ReportService(session)
        try:
            path = svc.export_to_file(rtype, title, {"summary": "Generated by ZorkSec."}, fmt)
            svc.generate(rtype, title, {"summary": "Generated by ZorkSec."}, fmt)
        except ValueError as exc:
            print(f"{_FAIL} {exc}")
            return 1
    print(f"{_OK} Report written: {path}")
    print(f"{_OK} Available formats: {', '.join(ReportService.formats())}")
    return 0


def _module_available(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zorksec",
        description=f"{__app_name__} - command-line interface",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--web", action="store_true", help="launch the web dashboard")
    parser.add_argument("--host", default=None, help="web bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="web bind port (default 8765)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="initialise ZorkSec (dirs, database, default user, catalog)")
    sub.add_parser("doctor", help="validate environment, dependencies, and database")
    sub.add_parser("version", help="print version information")
    sub.add_parser("discover", help="detect catalog tools already installed on this host")
    sub.add_parser("deps", help="show build/runtime dependency status")
    cat = sub.add_parser("catalog", help="list the tool catalog for a team profile")
    cat.add_argument("--team", choices=["blue", "red", "both"], default="both",
                     help="team profile to display (default: both)")
    tui = sub.add_parser("tui", help="launch the interactive terminal UI")
    tui.add_argument("--team", choices=["blue", "red", "both"], default="both",
                     help="team profile to load (default: both)")
    sub.add_parser("attack", help="show MITRE ATT&CK tactic coverage")
    diag = sub.add_parser("diagnose", help="run the Diagnostic Center system checks")
    diag.add_argument("--repair", action="store_true",
                      help="attempt safe auto-repairs for failing checks")
    rep = sub.add_parser("report", help="generate and export a SOC report")
    rep.add_argument("--type", choices=["incident", "threat_hunt", "dfir",
                                        "assessment", "executive"], default="incident")
    rep.add_argument("--title", default=None, help="report title")
    rep.add_argument("--format", choices=["markdown", "html", "json", "csv", "docx", "pdf"],
                     default="markdown")

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    if getattr(args, "web", False):
        return cmd_web(args)

    dispatch = {
        "init": cmd_init,
        "doctor": cmd_doctor,
        "version": cmd_version,
        "catalog": cmd_catalog,
        "discover": cmd_discover,
        "deps": cmd_deps,
        "tui": cmd_tui,
        "attack": cmd_attack,
        "diagnose": cmd_diagnose,
        "report": cmd_report,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        # No subcommand: launch the interactive TUI by default.
        return cmd_tui(args)
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
