#!/usr/bin/env bash
#
# ZorkSec - SOC L1 Learning Edition : maintenance & management script
# Author: Mohammad Muneeruddin (Muneer461 / Zork)
#
# Run this on your Kali Linux machine to manage your ZorkSec install. It offers
# three actions (interactive menu, or pass one directly as an argument):
#
#   1) Update      - pull the latest code and reinstall WITHOUT losing your data
#                    (your username/password, keys, reports and logs are kept).
#   2) Reinstall   - remove EVERYTHING, then install fresh from A to Z
#                    (this DOES erase your data, then sets it up clean).
#   3) Remove      - completely wipe ZorkSec and all stored data from the system
#                    (database with username/password, keys, logs, commands).
#
# Idempotent and safe to re-run. Honours a custom $ZORKSEC_HOME.
#
# Usage:
#   sudo ./manage.sh                 # show the interactive menu
#   sudo ./manage.sh update          # action 1 (keep data)
#   sudo ./manage.sh reinstall       # action 2 (wipe + fresh install)
#   sudo ./manage.sh remove          # action 3 (wipe only)
#   sudo ./manage.sh remove -y       # skip the confirmation prompt
#   ./manage.sh remove -n            # dry run: show what WOULD be removed
#   ./manage.sh -h                   # help
#
set -euo pipefail

ZORKSEC_HOME="${ZORKSEC_HOME:-/opt/zorksec}"
BIN_LINK="/usr/local/bin/zorksec"
ALIAS_LINK="/usr/local/bin/tools"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
INSTALLER="$SCRIPT_DIR/install.sh"

c_green="\033[1;32m"; c_yellow="\033[1;33m"; c_red="\033[1;31m"
c_cyan="\033[1;36m"; c_purple="\033[1;35m"; c_reset="\033[0m"
say()  { printf "%b[zorksec]%b %s\n" "$c_cyan" "$c_reset" "$1"; }
ok()   { printf "%b[ ok ]%b %s\n" "$c_green" "$c_reset" "$1"; }
warn() { printf "%b[warn]%b %s\n" "$c_yellow" "$c_reset" "$1"; }
die()  { printf "%b[fail]%b %s\n" "$c_red" "$c_reset" "$1"; exit 1; }

ASSUME_YES=0
DRY_RUN=0
ACTION=""

banner() {
  printf "%b\n" "$c_purple"
  cat <<'BANNER'
   ███████╗ ██████╗ ██████╗ ██╗  ██╗███████╗███████╗ ██████╗
   ╚══███╔╝██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝
     ███╔╝ ██║   ██║██████╔╝█████╔╝ ███████╗█████╗  ██║
    ███╔╝  ██║   ██║██╔══██╗██╔═██╗ ╚════██║██╔══╝  ██║
   ███████╗╚██████╔╝██║  ██║██║  ██╗███████║███████╗╚██████╗
   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
BANNER
  printf "%b" "$c_reset"
  printf "        %bSOC L1 Learning Edition%b  -  maintenance & management\n" "$c_cyan" "$c_reset"
  printf "        %bby Mohammad Muneeruddin (Muneer461 / Zork)%b\n\n" "$c_yellow" "$c_reset"
}

usage() {
  banner
  cat <<EOF
Manage your ZorkSec installation on Kali Linux.

Usage:
  sudo ./manage.sh                Show the interactive menu (3 options)
  sudo ./manage.sh update         1) Update - keep data, pull latest + reinstall
  sudo ./manage.sh reinstall      2) Reinstall - wipe everything, then fresh A-Z
  sudo ./manage.sh remove         3) Remove - completely wipe ZorkSec + all data
  ./manage.sh -h                  Show this help

Options:
  -y, --yes        Do not ask for confirmation (non-interactive)
  -n, --dry-run    For 'remove': list what WOULD be removed, change nothing

Honours \$ZORKSEC_HOME (default: /opt/zorksec).
EOF
}

# --- argument parsing ------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    update|--update)       ACTION="update" ;;
    reinstall|--reinstall) ACTION="reinstall" ;;
    remove|--remove|uninstall|--uninstall) ACTION="remove" ;;
    -y|--yes)              ASSUME_YES=1 ;;
    -n|--dry-run)          DRY_RUN=1 ;;
    -h|--help)             usage; exit 0 ;;
    *) die "Unknown argument: $1 (use -h for help)" ;;
  esac
  shift
done

# --- helpers ---------------------------------------------------------------
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "Please run with sudo:  sudo ./manage.sh"
  fi
}

confirm() {
  # $1 = prompt. Returns 0 to proceed, non-zero to abort. Respects -y.
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf "%b%s [y/N] %b" "$c_yellow" "$1" "$c_reset"
  if ! read -r reply; then
    die "No input (non-interactive shell). Re-run with -y to confirm."
  fi
  case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

resolve_user() {
  REAL_USER="${SUDO_USER:-$(id -un)}"
  REAL_HOME="$(eval echo "~${REAL_USER}" 2>/dev/null || echo "")"
}

collect_targets() {
  # Fills the EXISTING array with the ZorkSec paths that are present.
  case "$ZORKSEC_HOME" in
    ""|"/"|"/usr"|"/etc"|"/home"|"/root") die "Refusing: unsafe ZORKSEC_HOME='$ZORKSEC_HOME'" ;;
  esac
  resolve_user
  local targets=(
    "$ZORKSEC_HOME" "$BIN_LINK" "$ALIAS_LINK"
    "/root/.zorksec" "/root/.local/bin/zorksec" "/root/.local/bin/tools"
  )
  if [ -n "$REAL_HOME" ] && [ "$REAL_HOME" != "/root" ]; then
    targets+=(
      "$REAL_HOME/.zorksec" "$REAL_HOME/.local/bin/zorksec" "$REAL_HOME/.local/bin/tools"
    )
  fi
  EXISTING=()
  local t
  for t in "${targets[@]}"; do
    if [ -e "$t" ] || [ -L "$t" ]; then EXISTING+=("$t"); fi
  done
}

stop_processes() {
  say "Stopping any running ZorkSec process..."
  pkill -f 'zorksec.cli' 2>/dev/null || true
  pkill -f 'zorksec-launch.sh' 2>/dev/null || true
  sleep 1
}

# --- action: remove --------------------------------------------------------
do_remove() {
  # $1 = "force" to skip the per-action confirmation (used by reinstall).
  local force="${1:-}"
  [ "$DRY_RUN" -eq 1 ] || require_root
  collect_targets

  if [ "${#EXISTING[@]}" -eq 0 ]; then
    ok "Nothing to remove - ZorkSec is not installed (checked $ZORKSEC_HOME and launchers)."
    return 0
  fi

  say "The following ZorkSec items will be removed:"
  local t
  for t in "${EXISTING[@]}"; do
    if [ "$t" = "$ZORKSEC_HOME" ]; then
      printf "    %s   %b(includes the database with your username/password)%b\n" "$t" "$c_yellow" "$c_reset"
    else
      printf "    %s\n" "$t"
    fi
  done

  if [ "$DRY_RUN" -eq 1 ]; then
    ok "Dry run complete - nothing was changed."
    return 0
  fi

  if [ "$force" != "force" ]; then
    confirm "This permanently deletes all ZorkSec data. Continue?" || die "Aborted - nothing was removed."
  fi

  stop_processes
  for t in "${EXISTING[@]}"; do
    if rm -rf -- "$t" 2>/dev/null; then ok "Removed $t"; else warn "Could not remove $t"; fi
  done
  hash -r 2>/dev/null || true

  local leftover=()
  for t in "${EXISTING[@]}"; do
    { [ -e "$t" ] || [ -L "$t" ]; } && leftover+=("$t")
  done
  if [ "${#leftover[@]}" -eq 0 ]; then
    ok "ZorkSec was completely removed. No username, password, or stored data remains."
  else
    warn "Some items could not be removed:"
    for t in "${leftover[@]}"; do printf "    %s\n" "$t"; done
    die "Re-run with sudo, or remove the items above manually."
  fi
}

# --- action: update --------------------------------------------------------
do_update() {
  require_root
  [ -f "$INSTALLER" ] || die "install.sh not found next to this script ($SCRIPT_DIR); cannot update."
  say "Updating ZorkSec. Your data in $ZORKSEC_HOME (username/password, keys, reports) is preserved."
  confirm "Pull the latest version and reinstall the code?" || die "Aborted - nothing changed."

  if [ -d "$SCRIPT_DIR/.git" ]; then
    say "Pulling the latest code from git..."
    resolve_user
    if sudo -u "$REAL_USER" git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
      ok "Code updated from git."
    else
      warn "git pull failed (continuing with the local install.sh). You can run 'git pull' manually."
    fi
  fi

  say "Running the installer (idempotent - keeps your existing database)..."
  bash "$INSTALLER"
  ok "Update complete. Run 'hash -r' if the shell can't find the 'zorksec' command yet."
}

# --- action: reinstall (A to Z) --------------------------------------------
do_reinstall() {
  require_root
  [ -f "$INSTALLER" ] || die "install.sh not found next to this script ($SCRIPT_DIR); cannot reinstall."
  warn "Reinstall removes ALL ZorkSec data (including your username/password) and then installs fresh."
  confirm "Wipe everything and reinstall from scratch?" || die "Aborted - nothing changed."

  do_remove force
  printf "\n"
  say "Installing a fresh copy from scratch..."
  bash "$INSTALLER"
  ok "Reinstall complete. Default login is 'zorksec / zorksec' (you must change it on first login)."
}

# --- interactive menu ------------------------------------------------------
menu() {
  banner
  printf "  %b1)%b Update ZorkSec      %b(keep my data; pull latest + reinstall code & deps)%b\n" "$c_green" "$c_reset" "$c_cyan" "$c_reset"
  printf "  %b2)%b Reinstall A to Z    %b(remove EVERYTHING, then a clean fresh install)%b\n" "$c_green" "$c_reset" "$c_cyan" "$c_reset"
  printf "  %b3)%b Remove completely   %b(wipe all data, keys & commands from this system)%b\n" "$c_green" "$c_reset" "$c_cyan" "$c_reset"
  printf "  %bq)%b Quit\n\n" "$c_green" "$c_reset"
  printf "%bChoose an option [1/2/3/q]: %b" "$c_yellow" "$c_reset"
  if ! read -r choice; then
    die "No input (non-interactive shell). Pass an action directly, e.g.: sudo ./manage.sh remove -y"
  fi
  case "$choice" in
    1) ACTION="update" ;;
    2) ACTION="reinstall" ;;
    3) ACTION="remove" ;;
    q|Q|"") ok "Bye."; exit 0 ;;
    *) die "Invalid choice: $choice" ;;
  esac
}

# --- main ------------------------------------------------------------------
if [ -z "$ACTION" ]; then
  menu
fi

case "$ACTION" in
  update)    do_update ;;
  reinstall) do_reinstall ;;
  remove)    do_remove ;;
  *)         die "No action selected." ;;
esac
