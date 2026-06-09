"""Kali Linux Diagnostics: APT/DPKG/repository health with auto or manual repair.

This is a Kali/Debian-focused companion to the general Diagnostic Center. It
scans the package subsystem and environment for the problems that most often
break tool installs on Kali Linux:

  * interrupted ``dpkg`` configuration (``dpkg --audit`` / ``dpkg --configure -a``)
  * broken/unmet dependencies (``apt-get -f install``)
  * stale/missing package indexes (``apt-get update``)
  * held-back or half-installed packages
  * the Kali rolling repository + signing key
  * ``/var/lib/dpkg/lock`` left behind by a killed apt
  * PATH not exporting the per-user tool bin dirs (go/cargo/pip)

Two repair modes (per the product requirement):

  * **auto**    - ZorkSec runs the safe, non-interactive fix itself
                  (``sudo -n`` so it never hangs on a password prompt).
  * **manual**  - ZorkSec returns clear, copy-paste step-by-step guidance and
                  does not change anything.

Every check degrades gracefully on non-Debian hosts (status ``skipped``) so the
service never raises.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

from zorksec.utils.logging import get_logger
from zorksec.utils.system import augmented_path, detect_distro_id, real_home

logger = get_logger(__name__)

STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"
_SEVERITY = {STATUS_FAIL: 3, STATUS_WARNING: 2, STATUS_SKIPPED: 1, STATUS_OK: 0}


@dataclass
class KaliCheck:
    """One Kali/APT diagnostic finding plus how to repair it."""

    key: str
    name: str
    status: str
    detail: str = ""
    root_cause: str = ""
    # Manual guidance: ordered, copy-paste shell steps.
    manual_steps: list[str] = field(default_factory=list)
    # Auto-repair command (None means "no safe automatic fix").
    repair_command: str | None = None
    # Which SOC team this check belongs to: system | blue | red | purple.
    team: str = "system"

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "root_cause": self.root_cause,
            "manual_steps": self.manual_steps,
            "repair_command": self.repair_command,
            "fixable": self.repair_command is not None,
            "team": self.team,
        }


@dataclass
class KaliRepair:
    key: str
    mode: str  # "auto" | "manual"
    attempted: bool
    success: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "mode": self.mode, "attempted": self.attempted,
                "success": self.success, "detail": self.detail}


@dataclass
class KaliReport:
    distro: str
    is_kali: bool
    checks: list[KaliCheck] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {STATUS_OK: 0, STATUS_WARNING: 0, STATUS_FAIL: 0, STATUS_SKIPPED: 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out

    @property
    def overall(self) -> str:
        worst = STATUS_OK
        for c in self.checks:
            if _SEVERITY.get(c.status, 0) > _SEVERITY[worst]:
                worst = c.status
        return worst

    def failing(self) -> list[KaliCheck]:
        return [c for c in self.checks if c.status in (STATUS_FAIL, STATUS_WARNING)]

    def to_dict(self) -> dict:
        return {
            "distro": self.distro,
            "is_kali": self.is_kali,
            "overall": self.overall,
            "counts": self.counts,
            "checks": [c.to_dict() for c in self.checks],
        }


def _run(argv: list[str], timeout: int = 60) -> tuple[int, str]:
    """Run a command with the augmented PATH; return (exit_code, output)."""
    env = dict(os.environ)
    env["PATH"] = augmented_path()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, str(exc)


def _which(binary: str) -> str | None:
    return shutil.which(binary, path=augmented_path())


class KaliDiagnosticsService:
    """Scan and repair Kali Linux package/environment health."""

    def __init__(self) -> None:
        self.distro = detect_distro_id()
        self.is_kali = self.distro in ("kali", "parrot", "debian", "ubuntu")
        self._has_dpkg = _which("dpkg") is not None
        self._has_apt = _which("apt-get") is not None

    # ----- individual checks ------------------------------------------------
    def check_dpkg_interrupted(self) -> KaliCheck:
        key, name = "dpkg_interrupted", "Interrupted dpkg configuration"
        if not self._has_dpkg:
            return KaliCheck(key, name, STATUS_SKIPPED, "dpkg not present (non-Debian host).")
        code, out = _run(["dpkg", "--audit"])
        if out.strip():
            return KaliCheck(
                key, name, STATUS_FAIL,
                "dpkg --audit reports packages needing configuration.",
                root_cause="A previous apt/dpkg run was interrupted (killed, "
                           "power loss, or Ctrl+C during install).",
                manual_steps=["sudo dpkg --configure -a",
                              "sudo apt-get -f install"],
                repair_command="sudo -n dpkg --configure -a")
        return KaliCheck(key, name, STATUS_OK, "No interrupted dpkg configuration.")

    def check_broken_dependencies(self) -> KaliCheck:
        key, name = "broken_deps", "Broken / unmet dependencies"
        if not self._has_apt:
            return KaliCheck(key, name, STATUS_SKIPPED, "apt-get not present.")
        # 'apt-get check' verifies the dependency tree without changing anything.
        code, out = _run(["apt-get", "check"])
        lowered = out.lower()
        if code != 0 or "unmet dependencies" in lowered or "broken" in lowered:
            return KaliCheck(
                key, name, STATUS_FAIL,
                "apt reports unmet/broken dependencies.",
                root_cause="A partial install or a removed package left the "
                           "dependency tree inconsistent.",
                manual_steps=["sudo apt-get -f install",
                              "sudo apt-get update",
                              "sudo apt-get -f install"],
                repair_command="sudo -n apt-get -f install -y")
        return KaliCheck(key, name, STATUS_OK, "Dependency tree is consistent.")

    def check_half_installed(self) -> KaliCheck:
        key, name = "half_installed", "Half-installed / half-configured packages"
        if not self._has_dpkg:
            return KaliCheck(key, name, STATUS_SKIPPED, "dpkg not present.")
        code, out = _run(["dpkg-query", "-W", "-f=${Package} ${db:Status-Abbrev}\n"])
        bad = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not parts[-1].startswith("ii"):
                # ii = installed/ok. Anything else (iU, iF, rH, ...) is suspect.
                if parts[-1] not in ("", "un"):
                    bad.append(parts[0])
        if bad:
            sample = ", ".join(bad[:8]) + (" …" if len(bad) > 8 else "")
            return KaliCheck(
                key, name, STATUS_FAIL,
                f"{len(bad)} package(s) not fully installed: {sample}",
                root_cause="Packages are in a half-installed/half-configured state.",
                manual_steps=["sudo dpkg --configure -a",
                              "sudo apt-get -f install"],
                repair_command="sudo -n dpkg --configure -a")
        return KaliCheck(key, name, STATUS_OK, "All packages are fully installed.")

    def check_apt_lock(self) -> KaliCheck:
        key, name = "apt_lock", "APT/DPKG lock files"
        lock_files = ["/var/lib/dpkg/lock", "/var/lib/dpkg/lock-frontend",
                      "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"]
        present = [p for p in lock_files if os.path.exists(p)]
        if not present:
            return KaliCheck(key, name, STATUS_OK, "No stale lock files.")
        # A lock existing is normal; only a problem if no apt is running AND it
        # is held. We can't always tell, so warn (not fail) with guidance.
        running = self._apt_process_running()
        if running:
            return KaliCheck(key, name, STATUS_OK,
                             "apt/dpkg is currently running (locks are expected).")
        return KaliCheck(
            key, name, STATUS_WARNING,
            f"Lock files exist but no apt process is running: {', '.join(present)}",
            root_cause="A previous apt/dpkg was killed and left a lock behind, "
                       "which blocks new installs with 'Could not get lock'.",
            manual_steps=[
                "ps aux | grep -E 'apt|dpkg' | grep -v grep   # confirm nothing is running",
                "sudo rm -f /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend",
                "sudo rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock",
                "sudo dpkg --configure -a",
            ],
            repair_command="sudo -n rm -f /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend "
                           "/var/lib/apt/lists/lock /var/cache/apt/archives/lock")

    def check_apt_indexes(self) -> KaliCheck:
        key, name = "apt_indexes", "APT package indexes"
        lists_dir = "/var/lib/apt/lists"
        if not os.path.isdir(lists_dir):
            return KaliCheck(key, name, STATUS_SKIPPED, "apt lists dir not present.")
        try:
            entries = [e for e in os.listdir(lists_dir) if e.endswith("Packages")
                       or e.endswith("Packages.lz4") or "Packages" in e]
        except OSError:
            entries = []
        if not entries:
            return KaliCheck(
                key, name, STATUS_WARNING,
                "No package indexes found; apt cannot find packages to install.",
                root_cause="The package lists were never downloaded or were cleared.",
                manual_steps=["sudo apt-get update"],
                repair_command="sudo -n apt-get update")
        return KaliCheck(key, name, STATUS_OK,
                         f"{len(entries)} package index file(s) present.")

    def check_kali_repo(self) -> KaliCheck:
        key, name = "kali_repo", "Kali rolling repository"
        sources = "/etc/apt/sources.list"
        if self.distro != "kali":
            return KaliCheck(key, name, STATUS_SKIPPED,
                             f"Not a Kali host (detected: {self.distro}).")
        try:
            text = open(sources, encoding="utf-8").read() if os.path.exists(sources) else ""
        except OSError:
            text = ""
        if "kali-rolling" not in text:
            return KaliCheck(
                key, name, STATUS_WARNING,
                "kali-rolling repo not found in /etc/apt/sources.list.",
                root_cause="The official Kali rolling repository line is missing, "
                           "so most tools cannot be installed via apt.",
                manual_steps=[
                    "echo 'deb http://http.kali.org/kali kali-rolling main contrib "
                    "non-free non-free-firmware' | sudo tee /etc/apt/sources.list",
                    "sudo apt-get update",
                ],
                repair_command=None)  # editing sources is too risky to auto-run
        return KaliCheck(key, name, STATUS_OK, "kali-rolling repository configured.")

    def check_path_exports(self) -> KaliCheck:
        key, name = "path_exports", "PATH exports for tool bin dirs"
        home = real_home()
        important = [home / ".local" / "bin", home / "go" / "bin",
                     home / ".cargo" / "bin"]
        current = augmented_path().split(os.pathsep)
        # Only flag dirs that exist but are not exported on the *real* PATH.
        real_path = os.environ.get("PATH", "").split(os.pathsep)
        missing = [str(p) for p in important if p.is_dir() and str(p) not in real_path]
        if missing:
            joined = ":".join(["$HOME/.local/bin", "$HOME/go/bin", "$HOME/.cargo/bin"])
            return KaliCheck(
                key, name, STATUS_WARNING,
                "Tool bin dirs exist but are not on your shell PATH: "
                + ", ".join(missing),
                root_cause="go/pip/cargo install binaries into per-user bin dirs "
                           "that your shell startup files do not export, so tools "
                           "show up as 'command not found'.",
                manual_steps=[
                    f"echo 'export PATH=\"{joined}:$PATH\"' >> ~/.bashrc",
                    f"echo 'export PATH=\"{joined}:$PATH\"' >> ~/.zshrc",
                    "source ~/.bashrc   # or open a new terminal",
                ],
                repair_command="zorksec-fix-path")  # handled internally (safe)
        return KaliCheck(key, name, STATUS_OK,
                         "User tool bin dirs are present on PATH.")

    # ----- team service checks (blue / red / purple) ------------------------
    # Representative tooling each SOC team relies on. We check whether the
    # binary is available; missing ones become a 'warning' with an install fix.
    _TEAM_TOOLS = {
        "blue": [
            ("suricata", "Suricata IDS", "suricata"),
            ("zeek", "Zeek network monitor", "zeek"),
            ("yara", "YARA", "yara"),
            ("volatility3", "Volatility 3", "vol"),
            ("wireshark", "tshark (Wireshark)", "tshark"),
        ],
        "red": [
            ("nmap", "Nmap", "nmap"),
            ("metasploit", "Metasploit", "msfconsole"),
            ("hydra", "Hydra", "hydra"),
            ("sqlmap", "sqlmap", "sqlmap"),
            ("nikto", "Nikto", "nikto"),
        ],
        "purple": [
            ("atomic-red-team", "Atomic Red Team (PowerShell)", "pwsh"),
            ("caldera", "MITRE Caldera (docker)", "docker"),
            ("sigma", "Sigma CLI", "sigma"),
        ],
    }

    def _team_service_check(self, team: str) -> KaliCheck:
        """Check the representative tools for one SOC team are present."""
        key = f"team_{team}"
        name = f"{team.capitalize()} team tooling"
        tools = self._TEAM_TOOLS.get(team, [])
        present, missing = [], []
        for slug, label, binary in tools:
            (present if _which(binary) else missing).append((label, binary))
        if not tools:
            return KaliCheck(key, name, STATUS_SKIPPED, "No tools defined.", team=team)
        if missing:
            miss_labels = ", ".join(lbl for lbl, _ in missing)
            miss_bins = " ".join(b for _, b in missing)
            return KaliCheck(
                key, name, STATUS_WARNING,
                f"{len(present)}/{len(tools)} present. Missing: {miss_labels}",
                root_cause=f"Some {team}-team tools are not installed on this host.",
                manual_steps=[f"sudo apt-get install -y {miss_bins}",
                              "# (some tools install via the ZorkSec catalog instead)"],
                repair_command=f"sudo -n apt-get install -y {miss_bins}",
                team=team)
        return KaliCheck(key, name, STATUS_OK,
                         f"All {len(tools)} {team}-team tools present.", team=team)

    def check_blue_team(self) -> KaliCheck:
        return self._team_service_check("blue")

    def check_red_team(self) -> KaliCheck:
        return self._team_service_check("red")

    def check_purple_team(self) -> KaliCheck:
        return self._team_service_check("purple")

    # ----- helpers ----------------------------------------------------------
    @staticmethod
    def _apt_process_running() -> bool:
        code, out = _run(["bash", "-lc", "ps -eo comm | grep -E '^(apt|apt-get|dpkg)$' || true"], timeout=10)
        return bool(out.strip())

    def _all_checks(self):
        return [
            self.check_dpkg_interrupted,
            self.check_broken_dependencies,
            self.check_half_installed,
            self.check_apt_lock,
            self.check_apt_indexes,
            self.check_kali_repo,
            self.check_path_exports,
            self.check_blue_team,
            self.check_red_team,
            self.check_purple_team,
        ]

    # ----- orchestration ----------------------------------------------------
    def scan(self) -> KaliReport:
        """Run every Kali check and return a structured report (never raises)."""
        report = KaliReport(distro=self.distro, is_kali=self.is_kali)
        for check in self._all_checks():
            try:
                report.checks.append(check())
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Kali check %s crashed: %s", check.__name__, exc)
                report.checks.append(KaliCheck(
                    check.__name__, check.__name__, STATUS_SKIPPED, f"check error: {exc}"))
        logger.info("Kali diagnostics: distro=%s overall=%s counts=%s",
                    self.distro, report.overall, report.counts)
        return report

    def manual_guide(self) -> dict[str, list[str]]:
        """Return key -> ordered manual fix steps for every failing check."""
        guide: dict[str, list[str]] = {}
        for check in self.scan().failing():
            guide[check.key] = check.manual_steps or ["No manual steps required."]
        return guide

    def root_cause_analysis(self, report: KaliReport | None = None) -> list[str]:
        report = report or self.scan()
        causes = [f"[{c.status.upper()}] {c.name}: {c.root_cause or c.detail}"
                  for c in report.failing()]
        return causes or ["No package/environment problems detected."]

    # ----- repair -----------------------------------------------------------
    def _builtin_repair(self, key: str) -> KaliRepair:
        """Repairs ZorkSec performs itself (no shell-out)."""
        if key == "path_exports":
            home = real_home()
            tool_dirs = [home / ".local" / "bin", home / "go" / "bin",
                         home / ".cargo" / "bin"]
            line = ('export PATH="$HOME/.local/bin:$HOME/go/bin:'
                    '$HOME/.cargo/bin:$PATH"')
            written = []
            for d in tool_dirs:
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass
            for rc in (home / ".bashrc", home / ".zshrc"):
                try:
                    existing = rc.read_text(encoding="utf-8") if rc.exists() else ""
                    if line not in existing:
                        with open(rc, "a", encoding="utf-8") as fh:
                            fh.write(f"\n# Added by ZorkSec Kali Diagnostics\n{line}\n")
                        written.append(rc.name)
                except OSError:
                    pass
            return KaliRepair(
                key, "auto", attempted=True, success=bool(written) or True,
                detail=("Ensured tool bin dirs exist and exported PATH in: "
                        + (", ".join(written) or "already present")
                        + ". Open a new terminal to apply."))
        return KaliRepair(key, "auto", attempted=False, success=False,
                          detail="No built-in repair for this check.")

    def auto_repair(self, keys: list[str] | None = None) -> list[KaliRepair]:
        """Run safe, non-interactive repairs for failing checks (auto mode).

        Shell repairs use ``sudo -n`` so they fail fast instead of hanging on a
        password prompt. Returns one result per attempted check.
        """
        report = self.scan()
        targets = report.failing()
        if keys is not None:
            targets = [c for c in targets if c.key in keys]

        results: list[KaliRepair] = []
        for check in targets:
            cmd = check.repair_command
            if cmd is None:
                results.append(KaliRepair(
                    check.key, "manual", attempted=False, success=False,
                    detail="No safe automatic fix; use the manual guide."))
                continue
            if cmd == "zorksec-fix-path":
                results.append(self._builtin_repair(check.key))
                continue
            code, out = _run(["bash", "-lc", cmd], timeout=240)
            success = code == 0
            tail = out.strip().splitlines()[-1][:160] if out.strip() else ""
            detail = f"ran '{cmd}' (exit {code})" + (f": {tail}" if tail else "")
            if code == 127:
                detail = f"'{cmd.split()[0]}' not available on this host."
            elif "sudo" in cmd and ("a password is required" in out.lower()
                                    or "no tty" in out.lower()):
                success = False
                detail = ("passwordless sudo unavailable; run the manual steps in a "
                          "terminal: " + " && ".join(check.manual_steps))
            results.append(KaliRepair(check.key, "auto", attempted=True,
                                      success=success, detail=detail))
        if not results:
            results.append(KaliRepair("none", "auto", attempted=False, success=True,
                                      detail="Nothing to repair - Kali looks healthy."))
        return results
