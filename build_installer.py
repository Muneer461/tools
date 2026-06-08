#!/usr/bin/env python3
"""Generate a single self-extracting ``install.sh`` from the tested source tree.

Why generate instead of hand-write: the Python files in ``zorksec/`` are already
tested and runnable. This packager walks them and emits one idempotent bash
installer that recreates the exact tree under /opt/zorksec, sets up a venv, and
creates the ``tools`` command. Each embedded file uses a unique heredoc
delimiter and base64 encoding so source content (quotes, ``$``, ``EOF``) can
never corrupt the script.

Usage:  python build_installer.py            # writes install.sh
"""

from __future__ import annotations

import base64
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "install.sh"

# Files/dirs to embed (relative to repo root).
INCLUDE_DIRS = ["zorksec"]
INCLUDE_FILES = ["requirements.txt", "pyproject.toml"]
EXCLUDE_PARTS = {"__pycache__", ".pytest_cache"}

HEADER = r"""#!/usr/bin/env bash
#
# ZorkSec - SOC L1 Learning Edition : self-extracting installer
# Author: Mohammad Muneeruddin (Muneer461 / Zork)
#
# Idempotent: safe to re-run. Creates /opt/zorksec, a Python venv, writes all
# application files, and installs the global `tools` command.
#
set -euo pipefail

ZORKSEC_HOME="${ZORKSEC_HOME:-/opt/zorksec}"
BIN_LINK="/usr/local/bin/tools"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

c_green="\033[1;32m"; c_yellow="\033[1;33m"; c_red="\033[1;31m"; c_cyan="\033[1;36m"; c_reset="\033[0m"
say()  { printf "%b[zorksec]%b %s\n" "$c_cyan" "$c_reset" "$1"; }
ok()   { printf "%b[ ok ]%b %s\n" "$c_green" "$c_reset" "$1"; }
warn() { printf "%b[warn]%b %s\n" "$c_yellow" "$c_reset" "$1"; }
die()  { printf "%b[fail]%b %s\n" "$c_red" "$c_reset" "$1"; exit 1; }

# --- root check ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  die "Please run with sudo:  sudo ./install.sh"
fi

# Resolve the real (non-root) user so clones land in their home, not /root.
REAL_USER="${SUDO_USER:-$(id -un)}"
say "Installing ZorkSec to ${ZORKSEC_HOME} (invoking user: ${REAL_USER})"

# --- OS / dependency setup -------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
  say "Installing base dependencies via apt..."
  apt-get update -y >/dev/null 2>&1 || warn "apt-get update failed (continuing)"
  apt-get install -y python3 python3-venv python3-pip git >/dev/null 2>&1 \
    || warn "Some base packages may already be present"
else
  warn "apt-get not found; ensure python3 (>=3.10), python3-venv, pip and git are installed."
fi

# --- python version check --------------------------------------------------
PYBIN="$(command -v python3 || true)"
[ -n "$PYBIN" ] || die "python3 not found."
PYV_MAJOR="$($PYBIN -c 'import sys;print(sys.version_info[0])')"
PYV_MINOR="$($PYBIN -c 'import sys;print(sys.version_info[1])')"
if [ "$PYV_MAJOR" -lt "$PYTHON_MIN_MAJOR" ] || { [ "$PYV_MAJOR" -eq "$PYTHON_MIN_MAJOR" ] && [ "$PYV_MINOR" -lt "$PYTHON_MIN_MINOR" ]; }; then
  die "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ required (found ${PYV_MAJOR}.${PYV_MINOR})."
fi
ok "Python ${PYV_MAJOR}.${PYV_MINOR} detected"

# --- directory layout ------------------------------------------------------
mkdir -p "$ZORKSEC_HOME"
for d in core web tui plugins registry database reports logs config templates static; do
  mkdir -p "$ZORKSEC_HOME/$d"
done
ok "Directory layout ready"

# --- write embedded application files --------------------------------------
write_file() {
  # $1 = relative path, $2 = base64 payload
  local target="$ZORKSEC_HOME/$1"
  mkdir -p "$(dirname "$target")"
  printf '%s' "$2" | base64 -d > "$target"
}

say "Writing application files..."
"""

FOOTER = r"""
ok "Application files written"

# --- python virtual environment -------------------------------------------
VENV="$ZORKSEC_HOME/.venv"
if [ ! -d "$VENV" ]; then
  say "Creating virtual environment..."
  "$PYBIN" -m venv "$VENV"
fi
say "Installing Python dependencies (this can take a minute)..."
"$VENV/bin/pip" install --quiet --upgrade pip
if ! "$VENV/bin/pip" install --quiet -r "$ZORKSEC_HOME/requirements.txt"; then
  warn "Full dependency install failed; installing core set so the CLI still works."
  "$VENV/bin/pip" install --quiet sqlalchemy bcrypt cryptography rich || die "Core dependency install failed."
fi
ok "Dependencies installed"

# --- launcher + global symlink --------------------------------------------
LAUNCHER="$ZORKSEC_HOME/tools-launch.sh"
cat > "$LAUNCHER" <<'LAUNCHEOF'
#!/usr/bin/env bash
ZORKSEC_HOME="${ZORKSEC_HOME:-/opt/zorksec}"
exec "$ZORKSEC_HOME/.venv/bin/python" -m zorksec.cli "$@"
LAUNCHEOF
chmod +x "$LAUNCHER"
ln -sf "$LAUNCHER" "$BIN_LINK"
ok "Global command installed: tools -> $LAUNCHER"

# --- ownership + initialise -------------------------------------------------
chown -R "$REAL_USER":"$REAL_USER" "$ZORKSEC_HOME" 2>/dev/null || true
say "Initialising database, catalog, and default user..."
( cd "$ZORKSEC_HOME" && PYTHONPATH="$ZORKSEC_HOME" "$VENV/bin/python" -m zorksec.cli init ) || warn "init reported an issue"

# Re-fix ownership of any root-created runtime files (db, logs, key).
chown -R "$REAL_USER":"$REAL_USER" "$ZORKSEC_HOME" 2>/dev/null || true

printf "\n"
ok "ZorkSec installation complete!"
printf "%b\n" "${c_green}Next steps:${c_reset}"
printf "  tools            # launch the interactive terminal UI\n"
printf "  tools --web      # launch the web dashboard (http://127.0.0.1:8765)\n"
printf "  tools doctor     # verify the environment\n"
printf "\n  Default login: zorksec / zorksec  (you must change it on first login)\n"
"""


def iter_files():
    for d in INCLUDE_DIRS:
        for path in sorted((ROOT / d).rglob("*")):
            if path.is_dir():
                continue
            if any(part in EXCLUDE_PARTS for part in path.parts):
                continue
            if path.suffix == ".pyc":
                continue
            yield path
    for f in INCLUDE_FILES:
        p = ROOT / f
        if p.exists():
            yield p


def main() -> None:
    chunks: list[str] = [HEADER]
    count = 0
    for path in iter_files():
        rel = path.relative_to(ROOT).as_posix()
        payload = base64.b64encode(path.read_bytes()).decode("ascii")
        chunks.append(f'write_file "{rel}" "{payload}"\n')
        count += 1
    chunks.append(FOOTER)
    OUTPUT.write_text("".join(chunks), encoding="utf-8")
    OUTPUT.chmod(0o755)
    size_kb = OUTPUT.stat().st_size // 1024
    print(f"Wrote {OUTPUT} ({count} files embedded, {size_kb} KB)")


if __name__ == "__main__":
    main()
