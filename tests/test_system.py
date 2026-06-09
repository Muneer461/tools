"""Tests for system PATH helpers (the go-install 'not found' fix)."""

from __future__ import annotations

import os
from pathlib import Path

from zorksec.utils import system


def test_augmented_path_includes_go_bin(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    go_bin = fake_home / "go" / "bin"
    go_bin.mkdir(parents=True)

    monkeypatch.setattr(system, "real_home", lambda: fake_home)
    monkeypatch.setenv("PATH", "/usr/bin")

    path = system.augmented_path()
    assert str(go_bin) in path
    # original PATH preserved
    assert "/usr/bin" in path


def test_tool_env_has_augmented_path(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    (fake_home / ".cargo" / "bin").mkdir(parents=True)
    monkeypatch.setattr(system, "real_home", lambda: fake_home)

    env = system.tool_env()
    assert "PATH" in env
    assert str(fake_home / ".cargo" / "bin") in env["PATH"]


def test_extra_bin_dirs_skips_missing(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    # Only create one of the candidate dirs.
    (fake_home / ".local" / "bin").mkdir(parents=True)
    monkeypatch.setattr(system, "real_home", lambda: fake_home)
    monkeypatch.delenv("GOPATH", raising=False)

    dirs = [str(d) for d in system.extra_bin_dirs()]
    assert str(fake_home / ".local" / "bin") in dirs
    # A non-existent candidate should not be present.
    assert str(fake_home / "go" / "bin") not in dirs



# ---------------------------------------------------------------------------
# OS / distro detection (pre-install checks)
# ---------------------------------------------------------------------------
def test_detect_distro_returns_lowercase_string():
    """detect_distro_id never raises and returns a lowercase identifier."""
    from zorksec.utils import system

    distro_id = system.detect_distro_id()
    assert isinstance(distro_id, str)
    assert distro_id == distro_id.lower()
    assert distro_id != ""


def test_distro_summary_shape():
    from zorksec.utils import system

    summary = system.distro_summary()
    assert set(summary.keys()) == {"id", "label", "supported", "uses_apt"}
    assert isinstance(summary["supported"], bool)


def test_supported_distros_constant():
    from zorksec.utils import system

    assert "kali" in system.SUPPORTED_DISTROS
    assert "parrot" in system.SUPPORTED_DISTROS
