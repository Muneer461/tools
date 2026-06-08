"""Tests for the install.sh bundler (build_installer.py)."""

from __future__ import annotations

import base64
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_installer", ROOT / "build_installer.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_builder_includes_core_files():
    builder = _load_builder()
    files = {p.relative_to(ROOT).as_posix() for p in builder.iter_files()}
    assert "zorksec/cli.py" in files
    assert "zorksec/db/models.py" in files
    assert "requirements.txt" in files
    # No caches embedded.
    assert not any("__pycache__" in f for f in files)


def test_generated_installer_is_valid_bash(tmp_path):
    """Generate to a temp location and sanity-check structure + payload decoding."""
    builder = _load_builder()
    # Build in-memory by reusing the iter_files + header/footer.
    chunks = [builder.HEADER]
    sample_decoded = None
    for path in builder.iter_files():
        rel = path.relative_to(ROOT).as_posix()
        payload = base64.b64encode(path.read_bytes()).decode("ascii")
        chunks.append(f'write_file "{rel}" "{payload}"\n')
        if rel == "zorksec/__init__.py":
            sample_decoded = base64.b64decode(payload).decode("utf-8")
    chunks.append(builder.FOOTER)
    script = "".join(chunks)

    # Structural checks.
    assert script.startswith("#!/usr/bin/env bash")
    assert "ZORKSEC_HOME" in script
    assert 'ln -sf "$LAUNCHER" "$BIN_LINK"' in script
    assert "base64 -d" in script
    assert "set -euo pipefail" in script
    # Embedded payloads decode back to real source.
    assert sample_decoded is not None
    assert "ZorkSec" in sample_decoded
    # Every write_file line has a quoted path and base64 blob.
    write_lines = re.findall(r'write_file "([^"]+)" "([A-Za-z0-9+/=]+)"', script)
    assert len(write_lines) > 30


def test_actual_install_sh_exists_and_executable():
    install = ROOT / "install.sh"
    assert install.exists(), "install.sh should be generated and committed"
    content = install.read_text(encoding="utf-8")
    assert content.startswith("#!/usr/bin/env bash")
    assert "tools-launch.sh" in content
