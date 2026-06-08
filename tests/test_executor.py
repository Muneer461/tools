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
    cmd = build_install_command("pip", "volatility3", "volatility3")
    assert cmd.argv[:3] == ["python3", "-m", "pip"]
    assert "volatility3" in cmd.argv


def test_go_install_command():
    cmd = build_install_command("go", "github.com/x/y@latest", "y")
    assert cmd.argv == ["go", "install", "github.com/x/y@latest"]


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
