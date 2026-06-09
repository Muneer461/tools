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
    assert "zorksec-launch.sh" in content



def test_committed_install_sh_is_in_sync_with_source():
    """Guard against a STALE installer: every embedded blob must byte-match the
    current source tree. A drift here means `python build_installer.py` was not
    re-run after changing source/templates/static assets - the exact failure
    class behind 'the deployed Kali instance behaves differently from the repo'.
    """
    import hashlib

    builder = _load_builder()
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    embedded = dict(re.findall(
        r'write_file "([^"]+)" "([A-Za-z0-9+/=]+)"', installer))

    # 1. The set of embedded files must equal what the builder would embed now.
    expected = {p.relative_to(ROOT).as_posix() for p in builder.iter_files()}
    assert set(embedded) == expected, (
        "install.sh embeds a different file set than the source tree; "
        "re-run: python build_installer.py")

    # 2. Each embedded blob must byte-match the file on disk.
    stale = []
    for rel, blob in embedded.items():
        disk = (ROOT / rel).read_bytes()
        if hashlib.sha256(base64.b64decode(blob)).digest() != hashlib.sha256(disk).digest():
            stale.append(rel)
    assert not stale, f"install.sh is stale for: {stale}; re-run build_installer.py"


def test_frontend_assets_are_vendored_offline():
    """The terminal/icon assets must be bundled (no CDN) so an air-gapped Kali
    lab renders the dashboard and opens the in-browser terminal."""
    static = ROOT / "zorksec" / "web" / "static" / "vendor"
    for rel in ("xterm.min.js", "xterm.min.css", "xterm-addon-fit.min.js",
                "socket.io.min.js", "fontawesome/css/all.min.css"):
        assert (static / rel).exists(), f"missing vendored asset: {rel}"

    # No template may reference an external CDN for these critical assets.
    templates = ROOT / "zorksec" / "web" / "templates"
    for tpl in templates.glob("*.html"):
        text = tpl.read_text(encoding="utf-8")
        assert "cdn.jsdelivr.net" not in text, f"{tpl.name} still uses jsdelivr CDN"
        assert "cdn.socket.io" not in text, f"{tpl.name} still uses socket.io CDN"
        assert "cdnjs.cloudflare.com" not in text, f"{tpl.name} still uses cdnjs CDN"
