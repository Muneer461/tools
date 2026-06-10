#!/usr/bin/env bash
#
# ZorkSec - SOC L1 Learning Edition : one-click uninstaller
# Author: Mohammad Muneeruddin (Muneer461 / Zork)
#
# Removes EVERYTHING ZorkSec put on this system so you can install fresh:
#   * the install dir  /opt/zorksec  (database with your username/password,
#     master.key, secret.key, logs, reports, the venv, and all app files)
#   * the global commands  /usr/local/bin/zorksec  and  /usr/local/bin/tools
#   * legacy/stale copies from older installs (~/.zorksec, ~/.local/bin/*)
#
# Idempotent and safe to re-run. Honours a custom $ZORKSEC_HOME.
#
# Usage:
#   sudo ./uninstall.sh           # ask for confirmation, then remove
#   sudo ./uninstall.sh -y        # remove without the confirmation prompt
#   sudo ./uninstall.sh -n        # dry run: show what WOULD be removed
#   ./uninstall.sh -h             # help
#
set -euo pipefail

ZORKSEC_HOME="${ZORKSEC_HOME:-/opt/zorksec}"
BIN_LINK="/usr/local/bin/zorksec"
ALIAS_LINK="/usr/local/bin/tools"

c_green="\033[1;32m"; c_yellow="\033[1;33m"; c_red="\033[1;31m"; c_cyan="\033[1;36m"; c_reset="\033[0m"
say()  { printf "%b[zorksec]%b %s\n" "$c_cyan" "$c_reset" "$1"; }
ok()   { printf "%b[ ok ]%b %s\n" "$c_green" "$c_reset" "$1"; }
warn() { printf "%b[warn]%b %s\n" "$c_yellow" "$c_reset" "$1"; }
die()  { printf "%b[fail]%b %s\n" "$c_red" "$c_reset" "$1"; exit 1; }

ASSUME_YES=0
DRY_RUN=0

usage() {
  cat <<EOF
ZorkSec uninstaller - removes all ZorkSec data and commands from this system.

Usage:
  sudo ./uninstall.sh        Remove ZorkSec (asks for confirmation first)
  sudo ./uninstall.sh -y     Remove without asking (non-interactive)
  sudo ./uninstall.sh -n     Dry run - list what would be removed, change nothing
  ./uninstall.sh -h          Show this help

Honours \$ZORKSEC_HOME (default: /opt/zorksec).
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -y|--yes)     ASSUME_YES=1 ;;
    -n|--dry-run) DRY_RUN=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "Unknown option: $1 (use -h for help)" ;;
  esac
  shift
done

# --- safety guard: never operate on an empty or root path ------------------
case "$ZORKSEC_HOME" in
  ""|"/"|"/usr"|"/etc"|"/home"|"/root") die "Refusing: unsafe ZORKSEC_HOME='$ZORKSEC_HOME'" ;;
esac

# --- root check (needed for /opt and /usr/local/bin) -----------------------
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "Please run with sudo:  sudo ./uninstall.sh"
fi

# Resolve the real (non-root) user so we also clean their home dir, not /root.
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(eval echo "~${REAL_USER}" 2>/dev/null || echo "")"

# --- build the list of targets to remove -----------------------------------
TARGETS=(
  "$ZORKSEC_HOME"
  "$BIN_LINK"
  "$ALIAS_LINK"
  "/root/.zorksec"
  "/root/.local/bin/zorksec"
  "/root/.local/bin/tools"
)
if [ -n "$REAL_HOME" ] && [ "$REAL_HOME" != "/root" ]; then
  TARGETS+=(
    "$REAL_HOME/.zorksec"
    "$REAL_HOME/.local/bin/zorksec"
    "$REAL_HOME/.local/bin/tools"
  )
fi

# Keep only the ones that actually exist (-e covers files, dirs and symlinks).
EXISTING=()
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] || [ -L "$t" ] && EXISTING+=("$t")
done

if [ "${#EXISTING[@]}" -eq 0 ]; then
  ok "Nothing to remove - ZorkSec is not installed (checked $ZORKSEC_HOME and launchers)."
  exit 0
fi

say "The following ZorkSec items will be removed:"
for t in "${EXISTING[@]}"; do
  if [ "$t" = "$ZORKSEC_HOME" ]; then
    printf "    %s   %b(includes the database with your username/password)%b\n" "$t" "$c_yellow" "$c_reset"
  else
    printf "    %s\n" "$t"
  fi
done

if [ "$DRY_RUN" -eq 1 ]; then
  ok "Dry run complete - nothing was changed."
  exit 0
fi

# --- confirmation ----------------------------------------------------------
if [ "$ASSUME_YES" -eq 0 ]; then
  printf "%bThis permanently deletes all ZorkSec data. Continue? [y/N] %b" "$c_yellow" "$c_reset"
  if ! read -r reply; then
    die "No input (non-interactive shell). Re-run with -y to confirm."
  fi
  case "$reply" in
    y|Y|yes|YES) ;;
    *) die "Aborted - nothing was removed." ;;
  esac
fi

# --- stop any running ZorkSec process --------------------------------------
say "Stopping any running ZorkSec process..."
pkill -f 'zorksec.cli' 2>/dev/null || true
pkill -f 'zorksec-launch.sh' 2>/dev/null || true
sleep 1

# --- remove everything ------------------------------------------------------
for t in "${EXISTING[@]}"; do
  if rm -rf -- "$t" 2>/dev/null; then
    ok "Removed $t"
  else
    warn "Could not remove $t (check permissions / re-run with sudo)"
  fi
done

# --- forget cached command path in the current shell -----------------------
hash -r 2>/dev/null || true

# --- verify -----------------------------------------------------------------
LEFTOVER=()
for t in "${EXISTING[@]}"; do
  { [ -e "$t" ] || [ -L "$t" ]; } && LEFTOVER+=("$t")
done

printf "\n"
if [ "${#LEFTOVER[@]}" -eq 0 ]; then
  ok "ZorkSec was completely removed. No username, password, or stored data remains."
  printf "%b\n" "${c_green}Fresh install:${c_reset} run  ${c_cyan}sudo ./install.sh${c_reset}  then  ${c_cyan}hash -r${c_reset}"
else
  warn "Some items could not be removed:"
  for t in "${LEFTOVER[@]}"; do printf "    %s\n" "$t"; done
  die "Re-run with sudo, or remove the items above manually."
fi
