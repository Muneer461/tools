# ZorkSec Improvement Report

**Scope:** Security hardening, reliability, a new Diagnostic Center, and SOC
feature enhancements — delivered without rebuilding the existing architecture.
Root causes were fixed in place; all working components were preserved.

**Date:** 2026-06-09
**Test result:** ✅ **149 passed** (was 112 baseline; +37 new tests)

---

## 1. Fixed Issues

### Priority 1 — Security

| # | Issue | Fix |
|---|-------|-----|
| 1.1 | Socket.IO terminal endpoints were reachable without authentication | Added a `connect` handler that **rejects unauthenticated websockets**; every `start`/`input`/`resize` event now re-validates the session via `_socket_authenticated()` (defence-in-depth). |
| 1.2 | CORS used a wildcard (`cors_allowed_origins="*"`) — any site could drive the terminal | Restricted to an allow-list of **localhost + configured origins** (`Settings.allowed_origins()`), extendable via `ZORKSEC_ALLOWED_ORIGINS`. No wildcards. |
| 1.3 | No CSRF protection on forms | Added a per-session CSRF token (`csrf_token()` Jinja global) enforced in `before_request` for **login, change-password, forgot/reset-password, security-question, and profile/settings** forms. Hidden token fields added to all templates. |
| 1.4 | Password recovery had no throttling and leaked information | Now enforces **max 5 attempts**, **15-minute lockout**, **audit logging** of every attempt, and **generic error messages** (no user/answer enumeration). |
| 1.5 | A new Flask `SECRET_KEY` was generated on every restart (invalidating all sessions) | Persistent key management: `ZORKSEC_SECRET_KEY` env var → `.env` file → on-disk `config/secret.key` (mode 0600). **Never regenerated per restart.** |

Additional hardening: `HttpOnly` + `SameSite=Lax` session cookies and a
`PERMANENT_SESSION_LIFETIME` tied to the configured session timeout.

### Priority 2 — Reliability (installation integrity)

- **PATH verified before and after** each install; newly-added bin dirs are reported.
- **Binary existence verified** on the augmented PATH after install.
- **Version/help command executed** to prove the tool actually runs (`verify_tool()`).
- Tools are **marked installed only after validation succeeds**.
- **Improved logging and error reporting** throughout the install path; failures
  no longer silently report success.

### Priority 3 — Diagnostic Center (new)

New `DiagnosticService` + web page (`/diagnostics`), API
(`/api/diagnostics[/repair|/guide|/export]`), and CLI (`zorksec diagnose [--repair]`):

- **Full System Diagnostic**, **Auto Repair** (safe, non-interactive `sudo -n`
  + built-in PATH/permission fixes), **Manual Repair Guide**, **Root Cause
  Analysis**, and **Export Report** (markdown/html/json/csv).
- **Checks:** broken packages · DPKG · PATH · missing binaries · Python · Go ·
  Cargo · disk space · memory · network connectivity · permissions.
- Every check degrades gracefully to `unknown` on unsupported hosts (never raises).

### Priority 4 — SOC Enhancements

- **Catalog additions (now 96 tools):**
  - Threat Hunting: **Falco**, **Arkime** (plus existing Velociraptor, Osquery,
    Hayabusa, Chainsaw, YARA, Sigma).
  - Detection Engineering: **pySigma**, **Atomic Red Team**, **Caldera**,
    **VECTR**, **OSSEM** (plus existing Sigma).
  - SOC Utilities: **ATT&CK Navigator**, **tshark (PCAP analyzer)** (plus existing CyberChef).
- **New `SocUtilsService`:** IOC **parser** (refang + IP/domain/URL/hash/email),
  IOC **generator** (CSV / STIX-like JSON / defanged text), **log parser**
  (syslog / Combined Log Format / JSON / key=value), **PCAP analyzer** (tshark,
  best-effort), and CyberChef / ATT&CK Navigator integration links.
- **Threat intelligence lookup** already present (`/api/threatintel/lookup`).

---

## 2. Remaining Issues / Notes

- **Auto-repair shell actions** (`apt-get -f install`, `dpkg --configure -a`)
  require passwordless `sudo`; they use `sudo -n` and fail fast (reported, not
  hung) where that is unavailable. This is by design for safety.
- **GitHub/Docker-installed platforms** (e.g. MISP, TheHive, Arkime) have no
  single detection binary, so install verification reports "skipped runtime
  check" rather than a hard pass — accurate for multi-service platforms.
- **PCAP analysis** depends on `tshark` being installed (offered in the catalog);
  it degrades to a helpful message when absent.
- Optional report formats (**docx/pdf**) still require `python-docx` / `reportlab`;
  text formats are always available.

---

## 3. Security Findings (addressed)

| Severity | Finding | Status |
|----------|---------|--------|
| High | Unauthenticated Socket.IO command execution | ✅ Fixed (connect rejection + per-event session checks) |
| High | Wildcard CORS on the websocket layer | ✅ Fixed (origin allow-list) |
| High | Ephemeral secret key broke session integrity each restart | ✅ Fixed (persistent key) |
| Medium | No CSRF protection on auth/settings forms | ✅ Fixed (token + enforcement) |
| Medium | Password-recovery brute force + user enumeration | ✅ Fixed (lockout + generic errors + audit) |
| Low | Session cookies lacked HttpOnly/SameSite + timeout | ✅ Fixed |

---

## 4. Test Results

```
149 passed
```

Validation coverage includes:
- **Unit tests** — services (auth, executor, health, detection, dfir, catalog,
  diagnostic, soc_utils, system).
- **Integration tests** — web routes (dashboard, APIs, diagnostics, SOC utils).
- **Authentication tests** — login, lockout, password change, recovery lockout,
  generic errors, CSRF enforcement, Socket.IO auth accept/reject, secret-key
  persistence.
- **Tool discovery tests** — catalog seeding, installed-status sync, install
  verification.
- **PATH validation tests** — augmented PATH, extra bin dirs, install
  before/after PATH checks.

---

## 5. Tool Inventory

**96 tools** across **22 categories** (blue: 34, both: 30, red: 32).

| Category | # | Category | # |
|----------|---|----------|---|
| Information Gathering | 19 | Threat Hunting | 8 |
| OSINT for SOC | 8 | Forensics / DFIR | 7 |
| Web Application | 6 | Active Directory | 5 |
| Detection Engineering | 5 | Log Analysis | 4 |
| Threat Intelligence | 4 | Password Auditing | 4 |
| Incident Response | 3 | Network Monitoring | 3 |
| Wireless Security | 3 | Exploitation | 3 |
| SIEM / Logging | 2 | Phishing Analysis | 2 |
| Malware Analysis | 2 | Vulnerability Scanning | 2 |
| Post Exploitation | 2 | SOC Utilities | 2 |
| Reverse Engineering | 1 | Other | 1 |

---

## 6. Health Status

| Area | Status |
|------|--------|
| Build / packaging (`install.sh` regenerated, 60 files) | ✅ |
| Database init + migrations (additive columns applied) | ✅ |
| CLI (`init`, `doctor`, `diagnose`, `catalog`, …) | ✅ |
| Web dashboard + APIs | ✅ |
| Diagnostic Center | ✅ |
| Full test suite | ✅ 149 passed |

**Architecture preserved:** all changes were additive or in-place root-cause
fixes. No working component was rewritten.



---

## Addendum — v3.0 follow-up (applied within the existing architecture)

**Test result after this round:** ✅ **179 passed** (149 + 30 new).

| Item | Status | Where |
|------|--------|-------|
| Per-method install timeouts + process-group kill (BUG-10) | ✅ | `executor_service.py`: `INSTALL_TIMEOUTS`, watchdog-based `stream_command` (kills the whole group via `os.killpg`; returns 124), `install()` passes the per-method timeout and reports 124 distinctly |
| `tier` + `resource_class` on `ToolDef` | ✅ | `registry/catalog.py` (additive, default CORE/light) |
| Social Media OSINT category (OSINT-only, with disclaimers) | ✅ | `registry/catalog.py` `_SOCIAL`: PhoneInfoga, Ignorant, Social Analyzer, Blackbird, Osintgram (Sherlock/Maigret/Holehe already existed in "OSINT for SOC") |
| High-resource "type YES" warning + system RAM/disk/CPU comparison | ✅ | `resource_check_service.py`; wired into `ExecutorService.install(confirmed=…)` (returns 125 until confirmed), the Socket.IO install path, and `GET /api/tools/<slug>/resource-check` |
| Background Task Manager (QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED/TIMEOUT) | ✅ | `task_manager.py`: `submit/status/cancel/list_all/wait`, per-command timeouts, group-kill on timeout/cancel |
| Offline mode + `PENDING_ACTIONS.md` | ✅ | `offline_service.py`: `is_online()`, dedup queue, markdown render, `process_pending()` with 3 retries |
| Background + cached health engine (`tool_health.json`, 60-min TTL) | ✅ | `health_service.py`: `refresh_all`, cache helpers, `start_background_refresh` (own session, fail-safe); started in `run_web`; `zorksec health [--force]` CLI |
| PATH dedup hardening (v3.0 BUG-1 spec) | ✅ | `utils/system.py` `augmented_path` now de-duplicates the full PATH (order preserved) |

**New tests:** `test_paths.py`, `test_resource_check.py`, `test_task_manager.py`,
`test_offline.py`, plus health-cache cases in `test_health.py` and a heavy-tool
confirmation case in `test_executor.py`.

**Still deferred (documented, larger UI/scope):** "Top-20-per-category" catalog
expansion, login/dashboard visual redesign (matrix/glassmorphism), and the
first-login 3-step wizard UI (the underlying DB-backed password-change +
security-question flow already exists). Diagnostic export remains md/html/json/csv
(no PDF). These were left out deliberately to preserve the working architecture
and keep the suite green.
