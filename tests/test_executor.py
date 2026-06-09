"""Tests for executor command construction (pure, no execution)."""

from __future__ import annotations

import pytest

from zorksec.services.executor_service import (
    ExecutionError,
    build_install_command,
    stream_command,
    Command,
)


def test_apt_install_command():
    cmd = build_install_command("apt", "nmap", "nmap")
    assert cmd is not None
    assert cmd.argv == ["sudo", "apt-get", "install", "-y", "nmap"]
    assert cmd.shell is False


def test_pip_install_command():
    import sys
    cmd = build_install_command("pip", "volatility3", "volatility3")
    # Uses the running interpreter so the console script lands in a known bin dir.
    assert cmd.argv[:3] == [sys.executable, "-m", "pip"]
    assert "volatility3" in cmd.argv


def test_go_install_command():
    cmd = build_install_command("go", "github.com/x/y@latest", "y")
    # Go installs are a single shell command (shell=True) that pins GOBIN to
    # ~/go/bin so the resulting binary is always on the augmented PATH.
    assert cmd.shell is True
    assert "go install" in cmd.argv[0]
    assert "github.com/x/y@latest" in cmd.argv[0]
    assert "GOBIN=" in cmd.argv[0]


def test_github_clone_command_uses_soc_tools_dir():
    cmd = build_install_command("github", "Neo23x0/Loki", "loki")
    assert cmd.argv[0] == "git"
    assert cmd.argv[1] == "clone"
    assert cmd.argv[-2] == "https://github.com/Neo23x0/Loki.git"
    assert cmd.argv[-1].endswith("/soc_tools/github_repos/Loki")


def test_builtin_returns_none():
    assert build_install_command("builtin", "", "strings") is None


def test_unknown_method_raises():
    with pytest.raises(ExecutionError):
        build_install_command("brew", "x", "x")


def test_missing_target_raises():
    with pytest.raises(ExecutionError):
        build_install_command("apt", "", "x")


def test_stream_command_captures_output_and_exit_code():
    lines: list[str] = []
    cmd = Command(argv=["echo hello && exit 3"], description="t", shell=True)
    code = stream_command(cmd, on_line=lines.append)
    assert code == 3
    assert any("hello" in line for line in lines)



# ---------------------------------------------------------------------------
# Install verification (reliability): binary presence + version probe
# ---------------------------------------------------------------------------
from zorksec.services.executor_service import VerificationResult, verify_tool


def test_verify_tool_no_binary_is_ok():
    # 'cyberchef' is a browser tool with no detection binary -> skipped, ok.
    result = verify_tool("cyberchef")
    assert isinstance(result, VerificationResult)
    assert result.ok is True


def test_verify_tool_detects_present_binary(monkeypatch):
    import zorksec.services.executor_service as ex

    monkeypatch.setattr(ex, "_check_binary_for", lambda slug: "python3")
    result = verify_tool("fake-python-tool")
    assert result.ok is True
    assert result.binary == "python3"
    assert result.binary_present is True
    assert result.version_ok is True


def test_verify_tool_missing_binary_fails(monkeypatch):
    import zorksec.services.executor_service as ex

    monkeypatch.setattr(ex, "_check_binary_for",
                        lambda slug: "definitely-not-a-real-binary-xyz")
    result = verify_tool("ghost-tool")
    assert result.ok is False
    assert result.binary_present is False
    assert "not found" in result.reason


def test_verification_result_summary():
    ok = VerificationResult(slug="x", ok=True, binary="nmap",
                            binary_path="/usr/bin/nmap", version_output="Nmap 7.94")
    assert "verified" in ok.summary()
    bad = VerificationResult(slug="y", ok=False, reason="binary not found")
    assert "failed" in bad.summary()



# ---------------------------------------------------------------------------
# High-resource confirmation guard in install()
# ---------------------------------------------------------------------------
def test_install_heavy_tool_requires_confirmation(zorksec_home):
    from zorksec.db.session import init_db, session_scope
    from zorksec.services.executor_service import ExecutorService
    from zorksec.services.registry_service import RegistryService
    from zorksec.config import get_settings

    settings = get_settings()
    init_db(settings)
    lines: list[str] = []
    with session_scope(settings) as db:
        RegistryService(db).seed_catalog()
        # 'misp' is a heavy tool; without confirmation install must NOT run.
        code = ExecutorService(db).install("misp", lines.append, confirmed=False)
    assert code == 125
    assert any("HIGH RESOURCE WARNING" in ln for ln in lines)



# ---------------------------------------------------------------------------
# Run with user-supplied arguments (fixes "Run only prints --version")
# ---------------------------------------------------------------------------
from dataclasses import dataclass as _dataclass

from zorksec.services.executor_service import build_run_command


@_dataclass
class _FakeTool:
    slug: str
    install_method: str = "apt"
    install_target: str = "nmap"
    run_command: str = "nmap --version"


def test_run_command_default_is_catalog_command():
    cmd = build_run_command(_FakeTool(slug="nmap"))
    assert cmd.shell is True
    assert cmd.argv[0] == "nmap --version"


def test_run_command_with_extra_args_uses_binary(monkeypatch):
    # extra_args should produce '<binary> <args>' rather than the --version smoke check.
    cmd = build_run_command(_FakeTool(slug="nmap"), extra_args="-sV 127.0.0.1")
    assert cmd.shell is True
    assert cmd.argv[0] == "nmap -sV 127.0.0.1"
    assert "--version" not in cmd.argv[0]


def test_run_command_extra_args_falls_back_to_run_command_token():
    # A tool whose check_binary is empty in the catalog still runs via the
    # first token of its run_command.
    tool = _FakeTool(slug="nonexistent-slug", run_command="mytool --help")
    cmd = build_run_command(tool, extra_args="scan target")
    assert cmd.argv[0] == "mytool scan target"
