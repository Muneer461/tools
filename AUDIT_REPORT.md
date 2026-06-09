# ZorkSec Full Platform Audit & Remediation

Repository-wide audit covering architecture, UI, tool execution, terminal,
database, error handling, authentication, security, and testing. Runtime
button/terminal evidence lives in [`RUNTIME_DIAGNOSTICS.md`](RUNTIME_DIAGNOSTICS.md).

Verification baseline: **206 tests pass**, `ruff check zorksec/` clean,
`pip-audit` reports no known vulnerabilities.

---

## Phase 1 — Architecture

- **Stack:** Flask + Flask-SocketIO (gevent), SQLAlchemy + SQLite (WAL), Jinja
  templates, vanilla JS, xterm.js terminal over Socket.IO.
- **Layout:** `web/` (app, templates, static, terminal PTY), `services/`
  (auth, executor, registry, health, diagnostics, TI, SOC, DFIR, …),
  `repositories/` (data access), `db/` (models, session), `registry/catalog.py`
  (101-tool catalog), `detection/` (ATT&CK), `tui/`, `utils/`.
- **Execution model:** the browser sends a tool *slug* + action; the server
  builds the command from the **trusted catalog** (`executor_service`), never
  from raw client input. A separate, explicitly-flagged and audited free-form
  "lab command runner" exists for power users.
- **Auth:** login-required everywhere; forced first-login password change;
  session cookie hardened (HttpOnly, SameSite=Lax, lifetime); CSRF tokens on
  all state-changing forms; Socket.IO refuses unauthenticated connections.
- **Deploy:** `build_installer.py` packs the tested source tree into a single
  self-extracting `install.sh` (base64 blobs) that recreates `/opt/zorksec`,
  a venv, and the `zorksec` command.

## Phase 2 — UI audit

- Buttons, dropdowns, modals, cards, nav items traced; handlers
  (`openTerm`/`askRun`/`openDocs`/`runChoice`/`runCustom`) **register and fire**
  correctly (proven in `RUNTIME_DIAGNOSTICS.md`). No syntax errors, no missing
  listeners.
- **Fixed — team selector white-on-white:** the `<select>` had no `option`
  styling, so the native dropdown popup rendered white-on-white on some
  Linux/GTK browsers. Added explicit dark `option` colours in `zorksec.css`.
- **Fixed — installed-tools UX:** there was no way to see "installed tools".
  Added an **"Installed tools"** sidebar filter and made the **Installed** stat
  card clickable; tool cards now carry `data-installed`; an empty-state hint
  shows when nothing matches.
- **Fixed — offline icons:** Font Awesome vendored locally (was CDN).

## Phase 3 — Tool execution

- For every catalog tool, install/run commands and docs are derived from
  `registry/catalog.py` via `executor_service.build_install_command` /
  `build_run_command`. Routes (`/terminal`, `/api/run-target`, `/usage`,
  `/api/usage`) and the Socket.IO `start` handler all return/emit correctly.
- Heavy tools (e.g. BloodHound, Metasploit, Autopsy) require an explicit `YES`
  confirmation via `ResourceCheckService` before install — verified.
- Tools validated end-to-end through the executor/terminal path include Nmap,
  BloodHound, Impacket, NetExec, Responder, Kerbrute, Metasploit, Autopsy,
  Binwalk (and the rest of the 101-tool catalog) — see `tests/test_executor.py`,
  `tests/test_catalog.py`.

## Phase 4 — Terminal

- xterm.js + addon + socket.io now served **locally** (offline-safe).
- Backend flow proven: connect → `start` → `output` → `exit`
  (`RUNTIME_DIAGNOSTICS.md`, `tests/test_web.py::test_socketio_*`,
  `test_interactive_terminal_runs_initial_command_and_accepts_input`).
- The page keeps its graceful fatal-banner + connection watchdog for any
  residual load/connect failure, and offers the native-terminal fallback.

## Phase 5 — Database

- Root cause of `database is locked` identified and fixed (long write
  transaction held across network calls in the background health refresh).
  Details + regression test in `RUNTIME_DIAGNOSTICS.md` (Phase "database").
- WAL mode retained; `busy_timeout` raised 5s → 15s.

## Phase 6 — Error handling

- Added themed error pages + handlers for **400, 403, 404, 500** and a catch-all
  for unhandled exceptions (`templates/error.html`, handlers in `web/app.py`).
- 500s now log a full stack trace with a short reference id and show a friendly
  page instead of a raw Internal Server Error.
- Verified: `tests/test_web.py::test_404_returns_themed_error_page`.

## Phase 7 — Authentication & recovery

- **First-login wizard** extended: the forced password change now also requires
  creating a **recovery question + answer** in the same atomic transaction
  (if the question is rejected, the password change rolls back too).
- **Forgot-password flow** (already present, re-verified): username → show
  stored question → verify hashed answer (case-insensitive) → reset password,
  with attempt lockout.
- Answers stored hashed (never plaintext). Tests:
  `test_first_login_requires_recovery_question`,
  `test_first_login_wizard_sets_recoverable_question`,
  `test_security_question_set_then_recover`.

## Phase 8 — Security

- **Verified mitigations:** CSRF tokens on all state-changing forms; login
  required on every page/API; Socket.IO rejects unauthenticated sockets;
  restricted CORS allow-list (no wildcard); hardened session cookie; localhost
  binding until the default password is changed; persistent secret key;
  command building from a trusted catalog (not raw input); audit logging of all
  executions; clickjacking-resistant flows.
- **Accepted-by-design (documented):** `bandit` flags `shell=True` in
  `executor_service`, `task_manager`, `web/terminal.py`. This is intrinsic to a
  security-tool launcher: commands come from the curated catalog, and the
  free-form runner is explicitly flagged + audited. Inputs are not taken
  unsanitised from the network into a shell for catalog tools.
- `pip-audit`: no known vulnerabilities in dependencies.

## Phase 9 — Automated testing

| Tool | Result |
|------|--------|
| `pytest` | **206 passed** |
| `ruff check zorksec/` | clean |
| `pip-audit` | no known vulnerabilities |
| `bandit` | only intentional `shell=True` (see Phase 8) |
| `mypy` | pre-existing missing-stub / loose-typing notes only; none introduced by this change |

New tests added: error page, offline asset vendoring, installed filter,
cache-busting, first-login recovery wizard, installer-sync guard, DB-lock
regression.

## Phase 10 — Production validation

- Fresh provisioning verified (`zorksec.cli init` path / `ensure_default_user`).
- Login → forced wizard (password + recovery question) → dashboard → tool cards
  → terminal (local assets) → install/run/docs → docs page all exercised.
- `install.sh` regenerated and verified **byte-in-sync** with source (guarded by
  `tests/test_installer.py::test_committed_install_sh_is_in_sync_with_source`).

## Phase 11 — Delivery

- Branch: `audit/full-platform-remediation`.
- Changes committed logically; PR created with root causes, files changed,
  tests executed, and remaining risks. Not auto-merged.

---

## Remaining risks / follow-ups

- Headless Chromium could not run in the audit sandbox (missing `libnss3`),
  so screenshots were not captured here; JS/DOM behaviour was instead proven
  with Node + jsdom. Recommend a quick manual smoke test on a real Kali
  desktop after deploy.
- Google Fonts on the login page are still CDN-loaded (cosmetic; falls back to
  system fonts offline). Vendor later if fully offline typography is desired.
- `mypy` strictness and the pre-existing test-file lint nits can be cleaned up
  in a separate pass.
