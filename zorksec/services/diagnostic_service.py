"""Diagnostic Center: full system health checks, auto-repair, and reporting.

This service powers the ZorkSec "Diagnostic Center". It is intentionally
read-only by default; the only state-changing behaviour lives in
:meth:`DiagnosticService.auto_repair`, which runs *safe*, non-interactive
commands (``sudo -n`` so it never hangs waiting for a password).

Capabilities
------------
* Full System Diagnostic  - :meth:`run_full_diagnostic`
* Auto Repair             - :meth:`auto_repair`
* Manual Repair Guide     - :meth:`manual_repair_guide`
* Root Cause Analysis     - :meth:`root_cause_analysis`
* Export Report           - :meth:`export_report`

Checks: broken packages, dpkg issues, PATH, missing binaries, Python / Go /
Cargo environments, disk space, memory, network connectivity, and permissions.
Every check degrades gracefully (status ``unknown``/``skipped``) on hosts that
lack the relevant tooling so it never raises.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

from zorksec.utils.logging import get_logger
from zorksec.utils.system import augmented_path, real_home

logger = get_logger(__name__)

# Status vocabulary, ordered worst -> best for summarising.
STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_FAIL = "fail"
STATUS_UNKNOWN = "unknown"
_SEVERITY = {STATUS_FAIL: 3, STATUS_WARNING: 2, STATUS_UNKNOWN: 1, STATUS_OK: 0}


@dataclass
class CheckResult:
    key: str
    name: str
    status: str
    detail: str = ""
    root_cause: str = ""
    manual_fix: str = ""
    repair_command: str | None = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "root_cause": self.root_cause,
            "manual_fix": self.manual_fix,
            "repair_command": self.repair_command,
        }


@dataclass
class RepairResult:
    key: str
    attempted: bool
    success: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "attempted": self.attempted,
                "success": self.success, "detail": self.detail}


@dataclass
class DiagnosticReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {STATUS_OK: 0, STATUS_WARNING: 0, STATUS_FAIL: 0, STATUS_UNKNOWN: 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out

    @property
    def overall(self) -> str:
        worst = STATUS_OK
        for c in self.checks:
            if _SEVERITY[c.status] > _SEVERITY[worst]:
                worst = c.status
        return worst

    def failing(self) -> list[CheckResult]:
        return [c for c in self.checks
                if c.status in (STATUS_FAIL, STATUS_WARNING)]

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "counts": self.counts,
            "checks": [c.to_dict() for c in self.checks],
        }


def _run(argv: list[str], timeout: int = 20) -> tuple[int, str]:
    """Run a command (augmented PATH), returning (exit_code, combined_output)."""
    env = dict(os.environ)
    env["PATH"] = augmented_path()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, str(exc)


def _which(binary: str) -> str | None:
    return shutil.which(binary, path=augmented_path())


class DiagnosticService:
    """Runs system diagnostics, safe auto-repairs, and root-cause analysis."""

    # ----- individual checks ------------------------------------------------
    def check_broken_packages(self) -> CheckResult:
        name = "Broken packages"
        manual = ("Run 'sudo apt-get -f install' to fix unmet dependencies, then "
                  "'sudo apt-get update'.")
        if _which("dpkg-query") is None:
            return CheckResult("broken_packages", name, STATUS_UNKNOWN,
                               "dpkg not available on this host (non-Debian).",
                               manual_fix=manual)
        code, out = _run(["dpkg-query", "-W",
                          "-f=${Package} ${db:Status-Abbrev}\n"])
        broken = [ln for ln in out.splitlines()
                  if ln.strip() and not ln.split()[-1].startswith("ii")]
        if broken:
            return CheckResult(
                "broken_packages", name, STATUS_FAIL,
                f"{len(broken)} package(s) in a broken/half-installed state.",
                root_cause="An apt/dpkg operation was interrupted or hit unmet "
                           "dependencies.",
                manual_fix=manual, repair_command="sudo -n apt-get -f install -y")
        return CheckResult("broken_packages", name, STATUS_OK,
                           "No broken packages detected.")

    def check_dpkg(self) -> CheckResult:
        name = "DPKG integrity"
        manual = ("Run 'sudo dpkg --configure -a' to finish any interrupted "
                  "package configuration.")
        if _which("dpkg") is None:
            return CheckResult("dpkg", name, STATUS_UNKNOWN,
                               "dpkg not available on this host (non-Debian).",
                               manual_fix=manual)
        code, out = _run(["dpkg", "--audit"])
        if out.strip():
            return CheckResult(
                "dpkg", name, STATUS_FAIL,
                "dpkg --audit reported packages needing reconfiguration.",
                root_cause="A previous 'dpkg'/'apt' run was interrupted.",
                manual_fix=manual, repair_command="sudo -n dpkg --configure -a")
        return CheckResult("dpkg", name, STATUS_OK, "dpkg database is consistent.")

    def check_path(self) -> CheckResult:
        name = "PATH configuration"
        home = real_home()
        important = [home / ".local" / "bin", home / "go" / "bin",
                     home / ".cargo" / "bin"]
        current = augmented_path().split(os.pathsep)
        # Only flag dirs that exist on disk but are missing from PATH.
        missing = [str(p) for p in important if p.is_dir() and str(p) not in current]
        if missing:
            return CheckResult(
                "path", name, STATUS_WARNING,
                "Some user bin directories exist but are not on PATH: "
                + ", ".join(missing),
                root_cause="Shell startup files do not export these bin dirs, so "
                           "tools installed via pip/go/cargo are 'not found'.",
                manual_fix="Add 'export PATH=\"$HOME/.local/bin:$HOME/go/bin:"
                           "$HOME/.cargo/bin:$PATH\"' to your ~/.bashrc, then "
                           "open a new terminal.",
                repair_command="zorksec-fix-path")
        return CheckResult("path", name, STATUS_OK,
                           "User binary directories are present on PATH.")

    def check_missing_binaries(self) -> CheckResult:
        name = "Core binaries"
        essential = ["python3", "git"]
        missing = [b for b in essential if _which(b) is None]
        if missing:
            return CheckResult(
                "missing_binaries", name, STATUS_FAIL,
                "Essential tools missing: " + ", ".join(missing),
                root_cause="Required base tooling is not installed.",
                manual_fix="Install with 'sudo apt-get install -y "
                           + " ".join(missing) + "'.",
                repair_command="sudo -n apt-get install -y " + " ".join(missing))
        return CheckResult("missing_binaries", name, STATUS_OK,
                           "Essential binaries (python3, git) are present.")

    def check_python(self) -> CheckResult:
        import sys
        name = "Python environment"
        ver = ".".join(map(str, sys.version_info[:3]))
        if sys.version_info < (3, 10):
            return CheckResult(
                "python", name, STATUS_FAIL,
                f"Python {ver} is too old (ZorkSec needs >= 3.10).",
                root_cause="An old interpreter is the default 'python3'.",
                manual_fix="Install Python 3.10+ and run ZorkSec under it.")
        pip_ok = _which("pip3") is not None or _which("pip") is not None
        if not pip_ok:
            return CheckResult(
                "python", name, STATUS_WARNING,
                f"Python {ver} present but pip was not found.",
                root_cause="pip is not installed for this interpreter.",
                manual_fix="Install pip: 'sudo apt-get install -y python3-pip'.",
                repair_command="sudo -n apt-get install -y python3-pip")
        return CheckResult("python", name, STATUS_OK,
                           f"Python {ver} with pip available.")

    def _runtime_check(self, key: str, name: str, binary: str,
                       version_args: list[str], install_hint: str) -> CheckResult:
        if _which(binary) is None:
            return CheckResult(
                key, name, STATUS_WARNING,
                f"{name} not installed (optional, needed for some tools).",
                root_cause=f"The '{binary}' toolchain is not present.",
                manual_fix=install_hint,
                repair_command=None)
        code, out = _run([binary, *version_args])
        version = out.strip().splitlines()[0] if out.strip() else "unknown version"
        return CheckResult(key, name, STATUS_OK, f"{name} present: {version[:80]}")

    def check_go(self) -> CheckResult:
        return self._runtime_check(
            "go", "Go environment", "go", ["version"],
            "Install Go: 'sudo apt-get install -y golang-go'.")

    def check_cargo(self) -> CheckResult:
        return self._runtime_check(
            "cargo", "Cargo / Rust environment", "cargo", ["--version"],
            "Install Rust/Cargo: 'curl https://sh.rustup.rs -sSf | sh'.")

    def check_disk(self) -> CheckResult:
        name = "Disk space"
        try:
            usage = shutil.disk_usage("/")
        except OSError as exc:
            return CheckResult("disk", name, STATUS_UNKNOWN, f"Could not read: {exc}")
        free_gb = usage.free / (1024 ** 3)
        pct_used = usage.used / usage.total * 100 if usage.total else 0
        detail = f"{free_gb:.1f} GB free ({pct_used:.0f}% used)."
        if free_gb < 1 or pct_used > 95:
            return CheckResult(
                "disk", name, STATUS_FAIL, detail,
                root_cause="The root filesystem is nearly full.",
                manual_fix="Free space: 'sudo apt-get clean', remove old files, "
                           "or run 'docker system prune'.",
                repair_command="sudo -n apt-get clean")
        if free_gb < 5 or pct_used > 85:
            return CheckResult("disk", name, STATUS_WARNING, detail,
                               manual_fix="Consider freeing disk space soon.")
        return CheckResult("disk", name, STATUS_OK, detail)

    def check_memory(self) -> CheckResult:
        name = "Memory"
        try:
            import psutil  # type: ignore
        except ImportError:
            return CheckResult("memory", name, STATUS_UNKNOWN,
                               "psutil not installed; cannot read memory stats.",
                               manual_fix="Install psutil: 'pip install psutil'.")
        mem = psutil.virtual_memory()
        avail_mb = mem.available / (1024 ** 2)
        detail = f"{avail_mb:.0f} MB available ({mem.percent:.0f}% used)."
        if avail_mb < 256:
            return CheckResult(
                "memory", name, STATUS_FAIL, detail,
                root_cause="Very little RAM is available; tools may be killed.",
                manual_fix="Close other apps or add swap space.")
        if avail_mb < 512:
            return CheckResult("memory", name, STATUS_WARNING, detail,
                               manual_fix="Low memory; heavy tools may struggle.")
        return CheckResult("memory", name, STATUS_OK, detail)

    def check_network(self) -> CheckResult:
        name = "Network connectivity"
        import socket
        for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
            try:
                with socket.create_connection((host, port), timeout=4):
                    return CheckResult("network", name, STATUS_OK,
                                       "Outbound network connectivity confirmed.")
            except OSError:
                continue
        return CheckResult(
            "network", name, STATUS_WARNING,
            "No outbound connectivity detected (offline?).",
            root_cause="No route to the internet / DNS resolution blocked.",
            manual_fix="Check your network connection, proxy, or firewall. "
                       "Installs from apt/pip/go will fail while offline.")

    def check_permissions(self) -> CheckResult:
        name = "Permissions"
        from zorksec.config import get_settings
        settings = get_settings()
        problems: list[str] = []
        repair_cmd: str | None = None
        # Home directory writable?
        try:
            settings.home.mkdir(parents=True, exist_ok=True)
            probe = settings.home / ".diag_write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            problems.append(f"home not writable ({settings.home}): {exc}")
        # Secret/master key file permissions (should be 0600).
        for key_file in (settings.secret_key_file, settings.key_file):
            if key_file.exists():
                mode = os.stat(key_file).st_mode & 0o777
                if mode != 0o600:
                    problems.append(f"{key_file.name} mode is {oct(mode)} (want 0600)")
                    repair_cmd = "zorksec-fix-perms"
        if problems:
            return CheckResult(
                "permissions", name, STATUS_WARNING, "; ".join(problems),
                root_cause="ZorkSec files have unexpected ownership/permissions.",
                manual_fix="Ensure the ZorkSec home is owned by you and key files "
                           "are 'chmod 600'.",
                repair_command=repair_cmd)
        return CheckResult("permissions", name, STATUS_OK,
                           "Home directory writable and key files protected.")

    # ----- orchestration ----------------------------------------------------
    def _all_checks(self):
        return [
            self.check_broken_packages,
            self.check_dpkg,
            self.check_path,
            self.check_missing_binaries,
            self.check_python,
            self.check_go,
            self.check_cargo,
            self.check_disk,
            self.check_memory,
            self.check_network,
            self.check_permissions,
        ]

    def run_full_diagnostic(self) -> DiagnosticReport:
        """Run every check and return a structured report (never raises)."""
        report = DiagnosticReport()
        for check in self._all_checks():
            try:
                report.checks.append(check())
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Diagnostic check %s crashed: %s", check.__name__, exc)
                report.checks.append(CheckResult(
                    check.__name__, check.__name__, STATUS_UNKNOWN,
                    f"check error: {exc}"))
        logger.info("Diagnostic complete: overall=%s counts=%s",
                    report.overall, report.counts)
        return report

    # ----- manual guide -----------------------------------------------------
    def manual_repair_guide(self) -> dict[str, str]:
        """Return a key -> human-readable manual fix mapping for every check."""
        guide: dict[str, str] = {}
        for check in self._all_checks():
            try:
                result = check()
            except Exception:  # pragma: no cover
                continue
            guide[result.key] = result.manual_fix or "No manual action needed."
        return guide

    # ----- root cause -------------------------------------------------------
    def root_cause_analysis(self, report: DiagnosticReport | None = None) -> list[str]:
        """Summarise the likely root causes behind any failing checks."""
        report = report or self.run_full_diagnostic()
        causes: list[str] = []
        for c in report.failing():
            cause = c.root_cause or f"{c.name}: {c.detail}"
            causes.append(f"[{c.status.upper()}] {c.name}: {cause}")
        if not causes:
            causes.append("No problems detected - system looks healthy.")
        return causes

    # ----- auto repair ------------------------------------------------------
    def _builtin_repair(self, key: str) -> RepairResult:
        """Handle repairs ZorkSec performs itself (no shell-out)."""
        if key == "path":
            created = []
            # Create the standard user bin dirs so future installs land on PATH.
            home = real_home()
            for path in (home / ".local" / "bin", home / "go" / "bin",
                         home / ".cargo" / "bin"):
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    created.append(str(path))
                except OSError:
                    pass
            return RepairResult(
                key, attempted=True, success=bool(created),
                detail="Ensured user bin dirs exist: " + ", ".join(created)
                       + ". Add them to PATH in ~/.bashrc to persist.")
        if key == "permissions":
            from zorksec.config import get_settings
            settings = get_settings()
            fixed = []
            for key_file in (settings.secret_key_file, settings.key_file):
                if key_file.exists():
                    try:
                        os.chmod(key_file, 0o600)
                        fixed.append(key_file.name)
                    except OSError:
                        pass
            return RepairResult(key, attempted=True, success=bool(fixed),
                                detail="Reset permissions to 0600 on: "
                                       + (", ".join(fixed) or "nothing to fix"))
        return RepairResult(key, attempted=False, success=False,
                            detail="No built-in repair for this check.")

    def auto_repair(self, keys: list[str] | None = None) -> list[RepairResult]:
        """Attempt safe, non-interactive repairs for failing checks.

        Shell repairs use ``sudo -n`` so they fail fast rather than hanging on a
        password prompt. ZorkSec-internal repairs (PATH dirs, file permissions)
        are performed directly. Pass ``keys`` to repair specific checks only.
        """
        report = self.run_full_diagnostic()
        results: list[RepairResult] = []
        targets = report.failing()
        if keys is not None:
            targets = [c for c in targets if c.key in keys]

        for check in targets:
            cmd = check.repair_command
            if cmd is None:
                results.append(RepairResult(
                    check.key, attempted=False, success=False,
                    detail="No automatic repair; see the manual guide."))
                continue
            if not cmd.startswith("sudo") and cmd.startswith("zorksec-"):
                results.append(self._builtin_repair(check.key))
                continue
            code, out = _run(cmd.split(), timeout=120)
            success = code == 0
            detail = (f"ran '{cmd}' (exit {code})"
                      + (f": {out.strip().splitlines()[-1][:160]}" if out.strip() else ""))
            if code == 127:
                detail = f"'{cmd.split()[0]}' not available on this host."
            results.append(RepairResult(check.key, attempted=True,
                                        success=success, detail=detail))
        if not results:
            results.append(RepairResult("none", attempted=False, success=True,
                                        detail="Nothing to repair."))
        return results

    # ----- export -----------------------------------------------------------
    def export_report(self, report: DiagnosticReport | None = None,
                      fmt: str = "markdown", session=None) -> str:
        """Render the diagnostic report to a file and return its path."""
        from zorksec.config import get_settings
        from zorksec.services.report_service import ReportService

        report = report or self.run_full_diagnostic()
        context = {
            "summary": f"System diagnostic - overall status: {report.overall.upper()} "
                       f"({report.counts})",
            "findings": [f"[{c.status.upper()}] {c.name}: {c.detail}"
                         for c in report.checks],
            "remediation": self.root_cause_analysis(report),
        }
        settings = get_settings()
        svc = ReportService(session, settings) if session is not None \
            else _SessionlessReportExport(settings)
        return svc.export_to_file("assessment", "ZorkSec System Diagnostic",
                                  context, fmt)


class _SessionlessReportExport:
    """Render+write a report without a DB session (diagnostics may run early).

    Reuses the report renderer/templates but skips persistence so the
    Diagnostic Center can export even before the database is initialised.
    """

    def __init__(self, settings) -> None:
        self._settings = settings

    def export_to_file(self, report_type: str, title: str, context: dict,
                       fmt: str) -> str:
        import datetime as _dt

        from zorksec.config import ensure_directories
        from zorksec.services.report_service import build_template, render

        doc = build_template(report_type, title, context)
        content, ext = render(doc, fmt)
        ensure_directories(self._settings)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)[:60]
        stamp = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        path = self._settings.reports_dir / f"{safe}-{stamp}.{ext}"
        path.write_bytes(content)
        return str(path)
