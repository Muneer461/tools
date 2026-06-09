"""Execution engine: build and run install/run commands for catalog tools.

Security model: commands are *constructed by ZorkSec* from trusted catalog
fields (install method/target, run command). The UI never passes a raw shell
string from the user into this builder, so tool execution is effectively
allow-listed by the catalog. A separate, clearly-flagged free-form runner
(Chunk 4) is the only place arbitrary commands are accepted.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from shlex import quote as shlex_quote
from typing import Callable, Iterator

from sqlalchemy.orm import Session

from zorksec.db.models import ToolRegistry
from zorksec.repositories.history_repository import HistoryRepository
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger
from zorksec.utils.system import soc_tools_dir, tool_env

logger = get_logger(__name__)


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


def _repo_name(target: str) -> str:
    return target.rstrip("/").split("/")[-1]


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

    Returns the process exit code. ``on_line`` receives each line (without the
    trailing newline). Designed for live terminals; the web layer reuses the
    same builder with a PTY.
    """
    popen_kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
        "cwd": command.cwd,
        # Augment PATH so freshly go/cargo/pip-installed tools are found.
        "env": tool_env(),
    }
    if command.shell:
        proc = subprocess.Popen(command.argv[0], shell=True, **popen_kwargs)
    else:
        proc = subprocess.Popen(command.argv, **popen_kwargs)

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            if on_line:
                on_line(text)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        if on_line:
            on_line("[zorksec] command timed out and was terminated")
        return 124
    finally:
        if proc.stdout:
            proc.stdout.close()
    return proc.returncode if proc.returncode is not None else 1


class ExecutorService:
    """Ties command execution to the database (status + history)."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.tools = ToolRepository(session)
        self.history = HistoryRepository(session)

    def install(self, slug: str, on_line: Callable[[str], None] | None = None) -> int:
        tool = self.tools.get_by_slug(slug)
        if tool is None:
            raise ExecutionError(f"Unknown tool '{slug}'.")
        command = build_install_command(tool.install_method, tool.install_target, slug)
        if command is None:
            if on_line:
                on_line(f"[zorksec] '{tool.name}' is built-in / pre-installed; nothing to do.")
            self._mark_installed(tool, True)
            self.history.record(slug, "install", success=True, exit_code=0,
                                detail="builtin - no action")
            return 0
        if on_line:
            on_line(f"[zorksec] $ {command.display()}")
        code = stream_command(command, on_line)
        success = code == 0
        if success:
            # Verify the tool is actually runnable now (binary on the augmented
            # PATH). This catches cases where a package "installs" but its binary
            # is not yet findable, so the dashboard shows the true state.
            from zorksec.services.discovery_service import binary_present
            from zorksec.registry.catalog import CATALOG
            check_binary = next(
                (d.check_binary for d in CATALOG if d.slug == slug), "")
            runnable = (not check_binary) or binary_present(check_binary)
            self._mark_installed(tool, runnable)
            if on_line and check_binary and not runnable:
                on_line(f"[zorksec] note: '{check_binary}' installed but not yet on PATH; "
                        "open a new terminal or re-run discovery.")
        self.history.record(slug, "install", success=success, exit_code=code,
                            detail=command.display())
        return code

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
