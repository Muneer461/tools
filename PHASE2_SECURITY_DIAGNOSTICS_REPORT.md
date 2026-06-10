# Phase 2 — Security & Diagnostics Remediation

This pass addresses the three **High-risk, fully verifiable** items from the
Phase 2 brief without touching the stable Install / Run / Docs / terminal
execution chain (those tests pass unchanged). The remaining Phase 2 items
(profile system, AI online mode, full UI redesign, etc.) are intentionally out
of scope for this PR and are listed under "Not included" below.

## Scope guardrail

Per the brief, the Install button, Run button, Docs button, terminal execution,
and tool routing are treated as **stable** and were not modified. The full test
suite (including the terminal/PTY, run-command, and routing tests) was run
before and after every change.

- Baseline before changes: **214 passed**
- After changes (+ 4 new tests): **218 passed**

---

## Issue 1 — Security question change required no identity check (High)

### Root cause
`POST /security-question` called `AuthService.set_security_question()` directly
using only the logged-in session. Anyone with an open/hijacked session could
silently overwrite the account-recovery question and answer — the exact
credentials used to reset the password — with no re-authentication.

### Fix
The route now requires the user's **current password** and verifies it with
`AuthService.verify_password()` against the stored bcrypt hash before any
change is saved:

- Wrong/empty password → nothing is saved and the page shows
  **"Password verification failed."**
- Every attempt (success and failure) is written to the audit log
  (`security_question_set`, `success=True/False`).
- The success path and the `set_security_question` service are otherwise
  unchanged, so the first-login recovery-question wizard still works.

`security_question.html` gained a required `current_password` field.

**Files:** `zorksec/web/app.py`, `zorksec/web/templates/security_question.html`

### Evidence (tests)
- `test_security_question_requires_correct_password` — wrong password is
  rejected, no change saved, and the unsaved question is **not** exposed by the
  forgot-password flow.
- `test_security_question_correct_password_saves` — correct password saves.

---

## Issue 2 — Session survived a server restart (High)

### Root cause
Two correct-on-their-own behaviours combined into a weakness:
1. `Settings.resolve_secret_key()` **persists** the Flask `SECRET_KEY` to
   `config/secret.key` so sessions survive restarts by design.
2. Login sets `session.permanent = True` with a 30-minute lifetime.

Because the signing key is stable across restarts, a previously issued session
cookie stayed cryptographically valid after the server was restarted, so the
dashboard opened without re-authentication.

### Fix — bind sessions to a per-process boot id
- `create_app()` generates `app.config["ZORKSEC_BOOT_ID"] = secrets.token_hex(16)`
  once per process.
- Login stamps the session: `session["boot_id"] = ZORKSEC_BOOT_ID`.
- `_login_required` (and the Socket.IO `_socket_authenticated` gate) reject any
  session whose `boot_id` does not match the running process, clear it, and
  redirect to `/login`.
- Opt-out: set `ZORKSEC_PERSIST_SESSIONS=1` to deliberately keep sessions
  across restarts (e.g. multi-worker deployments behind a shared store).

A restart = a new process = a new boot id, so old cookies are refused. The
secret key still persists (so the cookie is not silently corrupted — it is
cleanly rejected and the user is redirected to log in).

**Files:** `zorksec/web/app.py`

### Evidence (tests)
- `test_session_does_not_survive_server_restart` — logs in fully on one app
  instance, copies the signed session cookie to a **second** freshly created
  app instance (simulating a restart), and asserts the reused cookie is
  redirected (302) to `/login`.

---

## Issue 3 — Diagnostics report could not be downloaded (High)

### Root cause
`POST /api/diagnostics/export` only wrote a file **on the server** and returned
its filesystem path. In a browser-only deployment the user never received a
file — there was no download, only a server-side path string in the status
line.

### Fix — true in-browser download
- New route `GET /api/diagnostics/download?format=<fmt>` renders the diagnostic
  report **in memory** (reusing the existing `report_service` renderer) and
  returns it via `send_file(..., as_attachment=True)` with a timestamped
  filename and correct MIME type.
- Formats: `json`, `csv`, `txt` (text/markdown body with a `.txt` name),
  `html`, `markdown`, plus optional `pdf`/`docx` when those libraries are
  installed. Unsupported formats return a clean `400 {"error": ...}`.
- `diagnostics.js` gained `downloadReport()`: it fetches the blob, triggers a
  real browser download (anchor + `URL.createObjectURL` / `revokeObjectURL`),
  and reports success ("Downloaded … (N bytes)") or a specific failure message.
- `diagnostics.html` now has a **Download Report** button and a TXT option; the
  previous server-side export is preserved as **Save on Server**.

**Files:** `zorksec/web/app.py`, `zorksec/web/static/diagnostics.js`,
`zorksec/web/templates/diagnostics.html`

### Evidence (tests)
- `test_diagnostics_download_returns_attachment` — `json`, `csv`, and `txt`
  each return `200`, a `Content-Disposition: attachment` header, the correct
  content type, and a non-empty body; the JSON download parses and is
  populated.

---

## Files modified

| File | Change |
|------|--------|
| `zorksec/web/app.py` | password check on security-question route; per-process boot-id session binding; `/api/diagnostics/download` route |
| `zorksec/web/templates/security_question.html` | required current-password field |
| `zorksec/web/templates/diagnostics.html` | Download button, TXT option, download URL |
| `zorksec/web/static/diagnostics.js` | `downloadReport()` blob download with feedback |
| `tests/test_web.py` | 4 new tests + updated existing recovery test |
| `install.sh` | regenerated to embed updated assets |

## Not included (remaining Phase 2 backlog)

These were **not** attempted in this PR and remain open: diagnostics dashboard
SOC-style redesign, auto-repair before/after evidence panel, profile picture
upload, edit-profile page, author-info panel, feedback button, per-tool usage
guidance database, full tool-catalog quality audit, Help Center redesign, AI
online mode + provider abstraction + API-key security, and the broader UI
modernization. They are larger, mostly UI-heavy efforts best delivered as
separate focused PRs.

## Remaining risks
- **Restart policy is process-scoped.** In a multi-worker / load-balanced
  deployment each worker has its own boot id, so a session would be re-auth'd
  when routed to a different worker. For that topology set
  `ZORKSEC_PERSIST_SESSIONS=1` and rely on the session lifetime instead. The
  default single-process `zorksec --web` is the intended target and behaves
  correctly.
- **No Kali click-through.** Validation here is the automated suite + route
  registration; a manual browser pass on Kali is still recommended.

## Deployment notes
- No DB schema or migration changes.
- New behaviour is backward compatible; the `?v=<mtime>` asset cache-buster
  invalidates the changed JS/CSS automatically.
- To keep the previous "sessions survive restart" behaviour, set
  `ZORKSEC_PERSIST_SESSIONS=1` in the environment.
