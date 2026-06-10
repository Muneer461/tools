# ZorkSec — SOC L1 Learning Edition

**Cybersecurity Analysis Platform (L1)** — a beginner‑friendly Security Operations
Center learning toolkit for **Kali / Parrot / Ubuntu** labs.

> Author: **Mohammad Muneeruddin (Muneer461 / Zork)**
> ⚠️ For authorized, isolated lab use and security education only.

---

## Table of Contents
1. [What is ZorkSec?](#what-is-zorksec)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Lab Setup (do this first)](#lab-setup-do-this-first)
5. [Installation](#installation)
6. [Launching ZorkSec](#launching-zorksec)
7. [First Login](#first-login)
8. [The Web Dashboard](#the-web-dashboard)
9. [CLI Commands](#cli-commands)
10. [Diagnostics & Help](#diagnostics--help)
11. [Troubleshooting](#troubleshooting)
12. [Manage: Update / Reinstall / Remove](#manage-update--reinstall--remove)
13. [Uninstall (manual)](#uninstall-manual)
14. [Security Notes](#security-notes)
15. [License & Disclaimer](#license--disclaimer)

---

## What is ZorkSec?
ZorkSec is a self‑contained platform that helps SOC L1 learners discover, install,
and practice with blue‑team and red‑team security tools in a safe lab. It provides:

- An **interactive terminal UI** (`zorksec`)
- A **web dashboard** with a live in‑browser terminal (`zorksec --web`)
- A curated **tool catalog** (blue / red / both) with health and install status
- **Diagnostics**, **Kali Diagnostics**, **Threat Intel**, **DFIR**, **Detection**,
  and **ATT&CK** workspaces
- An offline‑capable **AI assistant** and a **Help Center**

---

## Features
- **Tool catalog** organized by category and team (blue / red / both).
- **One‑click install / run / docs** for each tool, with PATH‑aware execution
  (finds tools installed via `apt`, `pip`, `go`, `cargo`, `snap`, `gem`).
- **Install verification** — a tool is only marked *installed* after its binary
  is found and a version/help probe succeeds.
- **Diagnostic Center** — full system checks (packages, dpkg, PATH, Python/Go/Cargo,
  disk, memory, network, permissions) with auto‑repair, manual guide, root‑cause
  analysis, and exportable reports.
- **Kali Linux Diagnostics** — apt/dpkg/repo/lock/PATH health plus Blue/Red/Purple
  team tooling checks, with **Auto fix** or **Manual steps**.
- **Help Center** — answers questions using internet search (with cited sources)
  and an offline knowledge base fallback.
- **Background task manager**, **offline mode** (queues actions to
  `PENDING_ACTIONS.md`), and **cached repository health**.
- **Security hardening** — CSRF protection, restricted CORS, authenticated
  Socket.IO, persistent secret key, password‑recovery lockout, forced first‑login
  password change, localhost‑only binding until the password is changed.

---

## Requirements
- **OS:** Kali Linux 2024+, Parrot OS 6, or Ubuntu 24.04 (Debian‑based).
- **Python:** 3.10 or newer.
- **Privileges:** `sudo` (the installer writes to `/opt/zorksec`).
- Packages installed automatically by the installer: `python3-venv`, `python3-pip`, `git`.

---

## Lab Setup (do this first)
1. Install a hypervisor: **VMware** or **VirtualBox**.
2. Create a **Kali VM** — this is where ZorkSec runs.
3. Add target VMs for practice: **Metasploitable2**, **DVWA**, **OWASP Juice Shop**.
4. Put all VMs on a **host‑only / internal** network — **never** bridge vulnerable
   VMs to the internet.
5. **Snapshot** every VM before each session so you can roll back safely.

---

## Installation
```bash
# 1) Get the project
git clone https://github.com/Muneer461/tools.git
cd tools

# 2) Run the installer (idempotent — safe to re-run)
chmod +x install.sh
sudo ./install.sh
```
The installer creates `/opt/zorksec`, a Python virtual environment, the global
`zorksec` command (plus a `tools` alias), and initializes the database, tool
catalog, and the default user.

> **First‑run tip:** if your shell says `zorksec: command not found` right after
> install, run `hash -r` (or open a new terminal) so the shell picks up the new
> command, or call it directly: `/usr/local/bin/zorksec`.

---

## Launching ZorkSec
```bash
zorksec            # interactive terminal UI (TUI)
zorksec --web      # web dashboard (auto-picks a free port, opens your browser)
zorksec doctor     # verify the environment
```

---

## First Login
Default credentials (first run only):

| Field | Value |
|-------|-------|
| Username | `zorksec` |
| Password | `zorksec` |

On first login you **must change the password**. You can also set a **security
question** for password recovery. Until the default password is changed, the web
dashboard binds to **127.0.0.1** only.

**Forgot your password?** Use the *Forgot password?* link on the login page (or
the *Recovery question* page) and answer your security question.

---

## The Web Dashboard
Start it with `zorksec --web`, then log in. From the dashboard you can:

- Browse tools by **category** in the sidebar.
- **Install** a tool, **Run** it (opens a live terminal in a new tab), or open
  its **Docs**.
- Use the **lab‑only command runner** to run audited commands.
- Watch live **CPU / Memory / Disk** metrics and recent activity.
- Open the **AI Assistant**, **Diagnostic Center**, **Kali Diagnostics**, and
  **Help Center**.

**Running a tool:** choose **In‑browser terminal** (new tab) or **Native Kali
terminal window**. If your browser blocks the new tab, ZorkSec falls back to
opening it in the same tab.

---

## CLI Commands
```bash
zorksec                      # launch the TUI
zorksec --web                # launch the web dashboard
zorksec init                 # initialize dirs, DB, catalog, default user
zorksec doctor               # environment / dependency / DB checks
zorksec diagnose [--repair]  # run the Diagnostic Center (optionally auto-repair)
zorksec health [--force]     # refresh repository health scores (cached 60 min)
zorksec discover             # detect catalog tools already installed
zorksec deps                 # show build/runtime dependency status
zorksec catalog --team blue  # list tools for a team (blue | red | both)
zorksec attack               # MITRE ATT&CK tactic coverage
zorksec report               # generate a report
```

---

## Diagnostics & Help
- **Diagnostic Center** (`/diagnostics` or `zorksec diagnose`): full system
  diagnostic, auto‑repair (safe, non‑interactive), manual repair guide,
  root‑cause analysis, and exportable report (Markdown / HTML / JSON / CSV).
- **Kali Diagnostics** (`/kali-diagnostics`): scans apt/dpkg/locks/repos/PATH and
  Blue/Red/Purple team tooling; choose **Auto fix** or **Manual steps** per issue.
- **Help Center** (`/help`): ask any question — online it searches the web and
  cites sources; offline it answers from a built‑in knowledge base.

---

## Troubleshooting
| Problem | Fix |
|--------|-----|
| `zorksec: command not found` after install | `hash -r` or open a new terminal; or run `/usr/local/bin/zorksec` |
| Python too old | Install Python 3.10+ and re‑run the installer |
| Port already in use | ZorkSec auto‑switches to a free port and prints the URL |
| In‑browser terminal stuck "connecting" | Ensure internet access for the xterm.js/Socket.IO CDN, or use the **Native Kali terminal** option |
| Permission errors during install | Run with `sudo` |
| Want a clean reset | Run `sudo ./manage.sh` and pick **Reinstall**, or see [Manage](#manage-update--reinstall--remove) |

---

## Manage: Update / Reinstall / Remove
The repo ships **`manage.sh`** — a single maintenance script for your Kali machine.
Run it and pick one of three options from the menu (it opens with the ZorkSec
banner):

```bash
cd tools                 # the cloned project folder
sudo ./manage.sh         # shows the menu below
```

```
  1) Update ZorkSec      (keep my data; pull latest + reinstall code & deps)
  2) Reinstall A to Z    (remove EVERYTHING, then a clean fresh install)
  3) Remove completely   (wipe all data, keys & commands from this system)
  q) Quit
```

| Option | What it does | Your data (username/password) |
|--------|--------------|-------------------------------|
| **1. Update** | `git pull` the latest code, then re‑run the installer (idempotent). | **Kept** |
| **2. Reinstall** | Wipe everything, then install fresh from A→Z. | **Erased**, then a clean default user is created |
| **3. Remove** | Completely uninstall: delete the install dir, keys, logs, and the global commands (incl. legacy copies). | **Erased** |

You can also run any option directly (handy for scripts):
```bash
sudo ./manage.sh update            # option 1
sudo ./manage.sh reinstall         # option 2
sudo ./manage.sh remove            # option 3
sudo ./manage.sh remove -y         # option 3, skip the confirmation prompt
./manage.sh remove -n              # dry run: list what WOULD be removed
./manage.sh -h                     # help
```
> `manage.sh` honours a custom `ZORKSEC_HOME` (e.g.
> `sudo ZORKSEC_HOME=/srv/zorksec ./manage.sh remove`), resolves your real
> (non‑root) user to clean their home folder too, and refuses unsafe paths.

### What gets removed (options 2 & 3)
| Path | Contents |
|------|----------|
| `/opt/zorksec/` | Database (**your username/password**), `master.key`, `secret.key`, logs, reports, `.venv`, all app files |
| `/usr/local/bin/zorksec`, `/usr/local/bin/tools` | The global launcher commands |
| `~/.zorksec`, `~/.local/bin/zorksec`, `~/.local/bin/tools` | Legacy/stale copies from older installs |

After **Reinstall** (or a fresh install) the login resets to the default
**`zorksec` / `zorksec`**, and you’ll be required to set a new password on first login.

---

## Uninstall (manual)
If you prefer not to use `manage.sh`, you can remove everything by hand:
```bash
# 1) Stop any running ZorkSec process
sudo pkill -f 'zorksec.cli' 2>/dev/null || true

# 2) Remove the install dir (database with username/password, keys, logs, venv, code)
sudo rm -rf /opt/zorksec

# 3) Remove the global commands
sudo rm -f /usr/local/bin/zorksec /usr/local/bin/tools

# 4) Remove legacy/stale copies from older installs
sudo rm -rf ~/.zorksec /root/.zorksec
rm -f ~/.local/bin/zorksec ~/.local/bin/tools

# 5) Forget the cached command path in the current shell
hash -r
```

### Verify it's completely gone
```bash
which zorksec tools     # should print nothing
ls /opt/zorksec         # should say: No such file or directory
```
If both come back empty, no username, password, or stored data remains.

---

## Security Notes
- Use ZorkSec only against systems you **own** or are **explicitly authorized** to test.
- Run offensive tools inside an **isolated lab network**, never against production
  or third‑party systems.
- The web dashboard stays on **localhost** until the default password is changed;
  keep it bound to localhost unless you fully understand the risk.
- Sessions use CSRF protection, restricted CORS, authenticated Socket.IO, and a
  persistent secret key.

---

## License & Disclaimer
This project is intended for **education and authorized security research only**.
The authors are not responsible for misuse. Always obtain written permission
before testing any system you do not own.

© Mohammad Muneeruddin (Muneer461 / Zork).
