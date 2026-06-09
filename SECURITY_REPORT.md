# ZorkSec Security Report

Scope: authentication, session security, route/WebSocket protection, command
execution, and client-side safety. Evidence is from live runs against the app.

## Authentication & first-login wizard

- Default `zorksec/zorksec` works only once; first login is **forced** through
  `/change-password`, which now requires a new password **and** a custom
  recovery question + answer in one atomic transaction (if the question is
  rejected, the password change rolls back). Proven: a submit without the
  question stays on the wizard and the dashboard remains locked.
- After the change, the **default password is permanently rejected**.
- Recovery answers are stored **hashed** and matched case-insensitively, with a
  max-attempt **lockout** and generic, non-enumerating errors.

## Route & session protection (verified by enumeration)

Auto-enumerated every rule in the URL map; with a fresh (logged-out) client,
**all 38 non-public routes** are blocked:
- pages (`/`, `/terminal`, `/usage`, `/lab`, `/diagnostics`, `/kali-diagnostics`,
  `/help`, `/security-question`) → `302 /login`
- every `/api/*` → `302 /login`
- state-changing POSTs without a token → `400` (CSRF guard) — action never runs

Public by design: `login`, `logout`, `forgot_password`, `reset_password`,
`static`. Locked-in by `test_every_route_requires_authentication`.

### Session hardening
- `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`,
  `PERMANENT_SESSION_LIFETIME` from `session_timeout_minutes`.
- Persistent `SECRET_KEY` (env / `.env` / on-disk `config/secret.key`, mode 0600).
- Per-session CSRF token enforced on login, password change, recovery, reset,
  security-question, and profile forms.

### WebSocket / terminal
- Socket.IO `connect` is **refused** for unauthenticated or not-yet-provisioned
  sessions; `start`/`input`/`resize` re-validate the session on every event.
- CORS is restricted to localhost + configured origins (no wildcard).

## Command execution

- Browser sends a tool **slug + action**; the server builds the command from
  the **trusted catalog** (`build_install_command` / `build_run_command`),
  never from arbitrary client strings.
- Heavy installs (BloodHound, Metasploit, Autopsy, …) require an explicit `YES`
  confirmation (`ResourceCheckService`).
- The free-form lab runner is explicitly flagged and **audit-logged**.
- `bandit` `shell=True` findings are intrinsic to the launcher and mitigated as
  above (see `TEST_REPORT.md`).

## Client-side safety

- All UI logic moved to external JS with event delegation — no inline `onclick`,
  so a future Content-Security-Policy can lock down inline scripts without
  breaking the UI.
- A site-wide error banner surfaces `window error` / `unhandledrejection` so
  failures are never silent.
- `askAi` renders replies with `textContent` (was `innerHTML`) — removes a
  reflected-XSS vector.
- Server-rendered dynamic content in diagnostics pages is HTML-escaped client-side.

## Residual notes

- `shell=True` is retained intentionally (documented).
- mypy strictness and pre-existing test-file lint nits are follow-ups.
