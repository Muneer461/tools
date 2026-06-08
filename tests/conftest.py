"""Shared pytest fixtures.

Each test runs against an isolated ZorkSec home in a temporary directory by
setting ``ZORKSEC_HOME`` before any module reads configuration.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


@pytest.fixture()
def zorksec_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point ZorkSec at a throwaway home and reset cached DB engine state."""
    home = tmp_path / "zorksec"
    monkeypatch.setenv("ZORKSEC_HOME", str(home))

    # Reset the module-level engine cache so the new home is used.
    import zorksec.db.session as session_mod

    importlib.reload(session_mod)
    yield home
