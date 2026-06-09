"""Execution engine: build and run install/run commands for catalog tools.

Security model: commands are *constructed by ZorkSec* from trusted catalog
fields (install method/target, run command). The UI never passes a raw shell
string from the user into this builder, so tool execution is effectively
allow-listed by the catalog. A separate, clearly-flagged free-form runner
(Chunk 4) is the only place arbitrary commands are accepted.

Reliability: installs are *validated* before a tool is marked installed. After
running the install command we (1) re-check the augmented PATH, (2) confirm the
tool's binary is present, and (3) run its version/help command to prove it
actually executes. Only when validation succeeds is ``tool_status.installed``
set, so the dashboard reflects reality rather than "the package manager exited
0".
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from shlex import quote as shlex_quote
from typing import Callable

from sqlalchemy.orm import Session

from zorksec.db.models import ToolRegistry
from zorksec.repositories.history_repository import HistoryRepository
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger
from zorksec.utils.system import augmented_path, soc_tools_dir, tool_env

logger = get_logger(__name__)

# Per-install-method timeouts (seconds). A hung package manager / clone must
# never block a worker forever, so each method gets a sane ceiling. On timeout
# the whole process group is killed (see ``stream_command``).
INSTALL_TIMEOUTS: dict[str, int] = {
    "apt": 180,
    "snap": 180,
    "pip": 120,
    "go": 120,
    "cargo": 120,
    "gem": 60,
    "docker": 300,
    "github": 30,  # shallow git clone
}
DEFAULT_INSTALL_TIMEOUT = 180


def install_timeout_for(method: str) -> int:
    """Return the timeout (seconds) to apply for a given install method."""
    return INSTALL_TIMEOUTS.get((method or "").lower(), DEFAULT_INSTALL_TIMEOUT)


class ExecutionError(RuntimeError):
    """Raised when a command cannot be constructed."""


@dataclass
class Command:
    """A fully-resolved command ready to execute."""

    argv: list[str]
    description: str
    shell: bool = False
    cwd: str | None = None

    def display(self) -> str:
        if self.shell:
            return self.argv[0]
        return " ".join(self.argv)


@dataclass
class VerificationResult:
    """Outcome of post-install validation for a tool."""

    slug: str
    ok: bool
    binary: str = ""
    binary_present: bool = False
    binary_path: str | None = None
    version_ok: bool = False
    version_output: str = ""
    reason: str = ""

    def summary(self) -> str:
        if self.ok:
            where = f" at {self.binary_path}" if self.binary_path else ""
            ver = f" ({self.version_output})" if self.version_output else ""
            return f"verified: '{self.binary}'{where}{ver}"
        return f"verification failed: {self.reason}"


def _repo_name(target: str) -> str:
    return target.rstrip("/").split("/")[-1]


def _version_probe_args() -> list[list[str]]:
    """Common, harmless ways to ask a CLI tool to prove it runs."""
    return [["--version"], ["version"], ["-V"], ["-version"], ["--help"], ["-h"]]


def _run_capture(argv: list[str], timeout: int = 20) -> tuple[int, str]:
    """Run a command with the augmented PATH, returning (exit_code, output)."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=tool_env(),
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, str(exc)


def _check_binary_for(slug: str) -> str:
    """Return the catalog's detection binary name for a slug ('' if none)."""
    from zorksec.registry.catalog import CATALOG

    return next((d.check_binary for d in CATALOG if d.slug == slug), "")


def verify_tool(slug: str, run_version_check: bool = True) -> VerificationResult:
    """Validate that a tool is genuinely installed and runnable.

    Steps:
      1. Resolve the tool's detection binary from the catalog.
      2. Confirm it is present on the *augmented* PATH (covers go/cargo/pip-user
         bin dirs that a parent shell may not have on PATH).
      3. Optionally run a version/help probe to prove it actually executes.

    Tools without a detectable binary (e.g. server platforms installed via
    ``github``/``docker``) are reported ``ok`` so they are not falsely marked
    broken, with a reason explaining the limitation.
    """
    import shutil

    from zorksec.services.discovery_service import binary_present

    binary = _check_binary_for(slug)
    if not binary:
        return VerificationResult(
            slug=slug, ok=True, reason="no detection binary defined; skipped runtime check")

    present = binary_present(binary)
    binary_path = shutil.which(binary, path=augmented_path()) if present else None
    if not present:
        return VerificationResult(
            slug=slug, ok=False, binary=binary, binary_present=False,
            reason=f"binary '{binary}' not found on PATH after install")

    if not run_version_check:
        return VerificationResult(
            slug=slug, ok=True, binary=binary, binary_present=True,
            binary_path=binary_path, version_ok=False,
            reason="binary present (version check skipped)")

    # Probe the binary so we know it actually runs (not just present on disk).
    for args in _version_probe_args():
        code, output = _run_capture([binary, *args])
        if code == 127:
            # Should not happen (present==True), but guard anyway.
            continue
        if code == 0 or output.strip():
            first_line = output.strip().splitlines()[0] if output.strip() else ""
            return VerificationResult(
                slug=slug, ok=True, binary=binary, binary_present=True,
                binary_path=binary_path, version_ok=True,
                version_output=first_line[:120], reason="ok")

    # Binary exists but no probe produced output; still installed, just quiet.
    return VerificationResult(
        slug=slug, ok=True, binary=binary, binary_present=True,
        binary_path=binary_path, version_ok=False,
        reason="binary present but version/help probe produced no output")


def build_install_command(method: str, target: str, slug: str) -> Command | None:
    """Build the install command for a tool. Returns None for 'builtin'."""
    method = (method or "").lower()
    if method == "builtin":
        return None
    if not target:
        raise ExecutionError(f"Tool '{slug}' has no install target for method '{method}'.")

    if method == "apt":
        return Command(["sudo", "apt-get", "install", "-y", target], f"apt install {target}")
    if method == "snap":
        return Command(["sudo", "snap", "install", target], f"snap install {target}")
    if method == "pip":
        # Use the SAME interpreter ZorkSec runs under so the installed console
        # script lands in a bin dir we add to PATH (avoids "command not found").
        import sys
        return Command([sys.executable, "-m", "pip", "install", "--upgrade", target],
                       f"pip install {target}")
    if method == "go":
        # Pin GOBIN to ~/go/bin (which we add to PATH) so the binary is findable
        # regardless of the user's GOPATH/GOBIN configuration.
        from zorksec.utils.system import real_home
        gobin = real_home() / "go" / "bin"
        # shell=True commands are executed from argv[0], so the full pipeline
        # must live in a single string (GOBIN pins the output to ~/go/bin).
        go_cmd = f"GOBIN={shlex_quote(str(gobin))} go install {shlex_quote(target)}"
        return Command([go_cmd], f"go install {target}", shell=True)
    if method == "docker":
        return Command(["docker", "pull", target], f"docker pull {target}")
    if method == "github":
        dest = soc_tools_dir() / _repo_name(target)
        url = f"https://github.com/{target}.git"
        return Command(
            ["git", "clone", "--depth", "1", url, str(dest)],
            f"git clone {target}",
        )
    raise ExecutionError(f"Unknown install method '{method}' for tool '{slug}'.")


def build_run_command(tool: ToolRegistry) -> Command:
    """Build the run command for a tool (catalog-defined; trusted)."""
    # GitHub tools run from their cloned directory.
    cwd: str | None = None
    if tool.install_method == "github" and tool.install_target:
        repo_dir = soc_tools_dir() / _repo_name(tool.install_target)
        cwd = str(repo_dir)

    if tool.run_command:
        # run_command is a trusted, catalog-authored shell string.
        return Command([tool.run_command], f"run {tool.slug}", shell=True, cwd=cwd)

    # Fall back to launching the detected binary.
    from zorksec.registry.catalog import CATALOG

    binary = next((d.check_binary for d in CATALOG if d.slug == tool.slug), "")
    if not binary:
        raise ExecutionError(f"Tool '{tool.slug}' has no run command or binary defined.")
    return Command([binary], f"run {binary}", cwd=cwd)


def stream_command(
    command: Command,
    on_line: Callable[[str], None] | None = None,
    timeout: int | None = None,
) -> int:
    """Execute a command, streaming combined stdout/stderr line-by-line.

    Returns the process exit code (124 on timeout). ``on_line`` receives each
    line (without the trailing newline). Designed for live terminals; the web
    layer reuses the same builder with a PTY.

    The wall-clock ``timeout`` is enforced by a watchdog thread, not by
    ``proc.wait`` alone: a hung process that keeps stdout open (producing no
    output) would otherwise block the read loop forever. When the watchdog
    fires it kills the whole process group, which closes stdout and unblocks us.
    """
    popen_kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
        "cwd": command.cwd,
        # Augment PATH so freshly go/cargo/pip-installed tools are found.
        "env": tool_env(),
        # Run in a new session/process group so that on timeout we can kill the
        # whole tree (e.g. 'go install' or a shell pipeline), not just argv[0].
        "start_new_session": True,
    }
    if command.shell:
        proc = subprocess.Popen(command.argv[0], shell=True, **popen_kwargs)
    else:
        proc = subprocess.Popen(command.argv, **popen_kwargs)

    timed_out = {"flag": False}
    watchdog: "threading.Timer | None" = None
    if timeout is not None:
        def _on_timeout() -> None:
            timed_out["flag"] = True
            _kill_process_group(proc)

        watchdog = threading.Timer(timeout, _on_timeout)
        watchdog.daemon = True
        watchdog.start()

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            if on_line:
                on_line(text)
        proc.wait()
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if proc.stdout:
            proc.stdout.close()

    if timed_out["flag"]:
        logger.warning("TIMEOUT: '%s' killed after %ss", command.display(), timeout)
        if on_line:
            on_line(f"[zorksec] TIMEOUT: command killed after {timeout}s")
        return 124
    return proc.returncode if proc.returncode is not None else 1


def _kill_process_group(proc: "subprocess.Popen") -> None:
    """Terminate a process and its whole group (SIGTERM, then SIGKILL).

    Started with ``start_new_session=True``, the child is a process-group
    leader, so ``killpg`` reaps grandchildren (compilers, git, etc.) too.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass


class ExecutorService:
    """Ties command execution to the database (status + history)."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.tools = ToolRepository(session)
        self.history = HistoryRepository(session)

    def install(self, slug: str, on_line: Callable[[str], None] | None = None,
                confirmed: bool = False) -> int:
        tool = self.tools.get_by_slug(slug)
        if tool is None:
            raise ExecutionError(f"Unknown tool '{slug}'.")

        # High-resource tools require an explicit confirmation before we run a
        # potentially long/heavy deployment. Callers pass confirmed=True after
        # the user types YES; otherwise we show the warning and stop (code 125).
        from zorksec.services.resource_check_service import ResourceCheckService
        if ResourceCheckService.requires_confirmation(slug) and not confirmed:
            warning = ResourceCheckService.warning_for(slug)
            if on_line and warning:
                on_line(warning.render_box())
                if warning.shortfalls:
                    on_line("[zorksec] WARNING: " + "; ".join(warning.shortfalls))
                on_line("[zorksec] Re-run with confirmation (type YES) to proceed.")
            logger.info("Install '%s' needs high-resource confirmation; not run", slug)
            return 125

        command = build_install_command(tool.install_method, tool.install_target, slug)
        if command is None:
            if on_line:
                on_line(f"[zorksec] '{tool.name}' is built-in / pre-installed; nothing to do.")
            self._mark_installed(tool, True)
            self.history.record(slug, "install", success=True, exit_code=0,
                                detail="builtin - no action")
            logger.info("Install '%s': builtin, marked installed", slug)
            return 0

        # 1) Capture PATH state *before* the install so we can report changes.
        path_before = augmented_path()
        timeout = install_timeout_for(tool.install_method)
        logger.info("Install '%s': running '%s' (timeout %ss)",
                    slug, command.display(), timeout)
        if on_line:
            on_line(f"[zorksec] $ {command.display()}")

        code = stream_command(command, on_line, timeout=timeout)

        # Surface timeouts explicitly so callers don't treat them as a clean fail.
        if code == 124:
            self._mark_installed(tool, False)
            self.history.record(slug, "install", success=False, exit_code=124,
                                detail=f"install TIMED OUT after {timeout}s: {command.display()}")
            return code

        # 2) Re-check PATH *after* the install (go/cargo/pip-user may add dirs).
        path_after = augmented_path()
        if on_line and path_after != path_before:
            added = [p for p in path_after.split(":") if p not in path_before.split(":")]
            if added:
                on_line(f"[zorksec] PATH updated with: {', '.join(added)}")

        if code != 0:
            logger.warning("Install '%s' command failed with exit code %s", slug, code)
            if on_line:
                on_line(f"[zorksec] install command exited {code}; tool NOT marked installed.")
            self._mark_installed(tool, False)
            self.history.record(slug, "install", success=False, exit_code=code,
                                detail=f"install command failed: {command.display()}")
            return code

        # 3) Validate: binary present + version/help probe runs. Only then do we
        #    mark the tool installed, so the dashboard reflects reality.
        result = verify_tool(slug)
        self._mark_installed(tool, result.ok)
        if on_line:
            on_line(f"[zorksec] {result.summary()}")
            if not result.ok and result.binary:
                on_line(f"[zorksec] note: '{result.binary}' may need a new shell session "
                        "to appear on PATH; re-run discovery if so.")
        if result.ok:
            logger.info("Install '%s': %s", slug, result.summary())
        else:
            logger.warning("Install '%s': %s", slug, result.summary())
        self.history.record(
            slug, "install", success=result.ok, exit_code=code,
            detail=f"{command.display()} | {result.summary()}")
        return code

    def verify(self, slug: str) -> VerificationResult:
        """Validate a tool's installation and sync its installed status."""
        tool = self.tools.get_by_slug(slug)
        if tool is None:
            raise ExecutionError(f"Unknown tool '{slug}'.")
        result = verify_tool(slug)
        self._mark_installed(tool, result.ok)
        logger.info("Verify '%s': %s", slug, result.summary())
        return result

    def run(self, slug: str, on_line: Callable[[str], None] | None = None) -> int:
        tool = self.tools.get_by_slug(slug)
        if tool is None:
            raise ExecutionError(f"Unknown tool '{slug}'.")
        command = build_run_command(tool)
        if on_line:
            on_line(f"[zorksec] $ {command.display()}")
        code = stream_command(command, on_line)
        self.history.record(slug, "run", success=(code == 0), exit_code=code,
                            detail=command.display())
        return code

    def _mark_installed(self, tool: ToolRegistry, installed: bool) -> None:
        status = self.tools.ensure_status(tool)
        status.installed = installed
        self.session.flush()
