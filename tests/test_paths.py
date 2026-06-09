"""PATH augmentation + install-timeout / process-group-kill tests."""

from __future__ import annotations

import time

from zorksec.services.executor_service import (
    Command,
    DEFAULT_INSTALL_TIMEOUT,
    install_timeout_for,
    stream_command,
)
from zorksec.utils.system import augmented_path, extra_bin_dirs, tool_env


def test_augmented_path_includes_interpreter_bin():
    import sys
    path = augmented_path()
    assert str(__import__("pathlib").Path(sys.executable).resolve().parent) in path


def test_augmented_path_dedupes_and_prepends():
    path = augmented_path().split(":")
    # No duplicate entries.
    assert len(path) == len(set(path))


def test_tool_env_sets_augmented_path():
    env = tool_env()
    assert env["PATH"] == augmented_path()


def test_extra_bin_dirs_only_existing():
    for d in extra_bin_dirs():
        assert d.is_dir()


def test_install_timeout_map():
    assert install_timeout_for("apt") == 180
    assert install_timeout_for("go") == 120
    assert install_timeout_for("github") == 30
    assert install_timeout_for("unknown-method") == DEFAULT_INSTALL_TIMEOUT


def test_stream_command_kills_hung_process_group():
    """A process holding stdout open via a child must be killed at the timeout."""
    start = time.time()
    code = stream_command(Command(["sleep 30 & wait"], "hang", shell=True),
                          None, timeout=2)
    elapsed = time.time() - start
    assert code == 124          # timeout sentinel
    assert elapsed < 10         # killed promptly, not after 30s


def test_stream_command_runs_to_completion():
    lines: list[str] = []
    code = stream_command(Command(["echo zorksec-ok"], "echo", shell=True),
                          lines.append, timeout=10)
    assert code == 0
    assert any("zorksec-ok" in ln for ln in lines)
