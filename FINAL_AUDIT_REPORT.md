# ZorkSec — Full Repository Audit & Auto-Repair Report

**Date:** 2026-06-09 · **Mode:** evidence-based audit + safe auto-fix · **Architecture:** preserved

All conclusions below are backed by command output. Live web-server launches were
deliberately avoided after confirming they block by design; the web layer is
validated non-blockingly via the WSGI test client (real HTTP status codes).

---

## Validation summary (after fixes)

| Check | Result | Evidence |
|-------|--------|----------|
| Lint (ruff) | ✅ All checks passed | `ruff check zorksec` → "All checks passed!" |
| Unit + integration tests | ✅ **179 passed** | `pytest -q` exit 0 |
| Import graph | ✅ 49 modules, 0 failures, no circular imports | `pkgutil.walk_packages` import-all |
| App factory + routes (HTTP) | ✅ 200/302 as expected | WSGI test client smoke (below) |
| Tool registry | ✅ 101 tools, 0 defects | catalog validator |
| DB integrity | ✅ FKs + cascades correct | `models.py` inspection |
| Secrets scan | ✅ none beyond documented default | grep |

WSGI HTTP smoke (non-blocking):
```
GET /login          -> 200 (renders ZorkSec)
GET / (no auth)     -> 302 (redirect to login)
GET / (auth)        -> 200 (dashboard loads)
GET /diagnostics    -> 200
GET /api/diagnostics-> 200 (overall: unknown)
GET /api/tools      -> 200 (101 tools)
resource-check/misp -> 200 (requires_confirmation: True)
```

---

## Phase 1 — Repository discovery

| Metric | Value |
|--------|-------|
| Python files (`zorksec/`) | 50 |
| Test files | 21 |
| Test functions | ~171 (179 collected w/ params) |
| Templates (HTML) | 10 |
| Services | 21 |
| Entry points | `zorksec/cli.py` (CLI), `zorksec/web/app.py` (`create_app`/`run_web`), `zorksec/tui/app.py` (TUI) |
| Runtime deps | SQLAlchemy, bcrypt, cryptography, rich, Flask, Flask-SocketIO, gevent, gevent-websocket, Jinja2, requests, distro, psutil |

Service graph: services depend on `repositories/` (data access) → `db/` (SQLAlchemy models); `registry/catalog.py` is a standalone dataclass list. No service↔service cycles.

---

## Phase 2 — Static analysis

`ruff check zorksec` initially reported **11 issues**. Breakdown and resolution:

| Rule | Count | Files | Severity | Action |
|------|-------|-------|----------|--------|
| F401 unused import | 7 | models.py (`Float`), attack_service.py (×3), executor_service.py (`field`,`Path`,`Iterator`), task_manager.py (`field`) | Low (dead code) | ✅ removed (auto-fix) |
| F821 undefined name `Report` | 1 | report_service.py:286 | **Medium** (latent: annotation references unimported name; breaks `get_type_hints`/type-checkers) | ✅ added `TYPE_CHECKING` import |
| E731 lambda assignment | 1 | tui/app.py:212 | Low (style) | ✅ rewritten as `def` |
| F541 f-string w/o placeholder | 1 | tui/app.py:222 | Low (style) | ✅ removed `f` prefix |

Other static checks:
- **Circular/broken imports:** none (49/49 modules import).
- **`eval`/`exec`/`pickle`/`yaml.load`:** none found.
- **Blocking subprocess without timeout:** none — every `subprocess.run` carries `timeout=`; the streaming runner uses a watchdog (see Phase 5).

---

## Phase 3 — Security audit

| Control | Status | Evidence |
|---------|--------|----------|
| AuthN (login, lockout) | ✅ | `auth_service`; bcrypt hashing; failed-login lockout |
| AuthZ (route guard) | ✅ | every route `@_login_required` except intentional public auth endpoints |
| Sessions | ✅ | HttpOnly + SameSite=Lax + timeout + permanent |
| Password storage | ✅ | bcrypt (`security/crypto.py`) |
| CSRF | ✅ | token + `hmac.compare_digest` on login/recovery/settings forms |
| CORS | ✅ | localhost allow-list, no wildcard |
| Command injection | ✅ low risk | commands built from trusted catalog fields; shell pipelines use `shlex.quote` |
| Secrets mgmt | ✅ | env / `.env` / on-disk 0600; no hardcoded secrets (default login is documented first-run credential) |
| Socket.IO | ✅ | `connect` rejects unauth; `start`/`input`/`resize` re-check session |

No new high/critical security defects found this pass.

---

## Phase 4 — Tool registry audit

Validator output: **101 tools**, and **zero** of: invalid install method, invalid team, missing install target (non-builtin), missing beginner note, malformed `owner/repo` GitHub slug, duplicate slug.

---

## Phase 5 — Installation / PATH audit

- `augmented_path()` covers go/cargo/pip-user/gem/snap/venv and now **de-duplicates the full PATH**.
- Used in: executor (`tool_env`), discovery (`binary_present`), web terminal (PTY child sets `PATH`).
- pip installs use `sys.executable -m pip`; go installs pin `GOBIN=~/go/bin`.
- Per-method install timeouts (apt 180s / go,pip,cargo 120s / git 30s / docker 300s) enforced by a **watchdog thread** that kills the whole **process group** (`os.killpg`) — verified: a hung `sleep 30 & wait` is killed at 2s (exit 124).
- Post-install verification (`verify_tool`): binary presence + version/help probe; installed flag set only on success.

---

## Phase 6 — Database audit

All models use SQLAlchemy 2.0 typed mappings. Foreign keys (`tool_status`, `tool_health`, `api_keys`, `learning_progress`) use `ondelete="CASCADE"` with matching `relationship(cascade="all, delete-orphan")`. Additive migration path handles new columns (`security_question`, `recovery_*`). No orphan-prone relationships found.

---

## Phase 7 — API audit

Every `@app.route` is `@_login_required` except `/login`, `/logout`, `/forgot-password`, `/reset-password` (intentionally public for the auth/recovery flow). State-changing form endpoints are CSRF-protected; JSON APIs are same-origin + login-gated. Error handling returns structured 400/JSON for known failure modes.

---

## Phase 8 — UI audit

10 templates render via Jinja with a shared `base.html`. Login/dashboard/diagnostics confirmed to return HTTP 200 through the test client. CSRF hidden fields present on all forms. (Deep client-side JS/accessibility/mobile review remains a recommended future task — see Remaining.)

---

## Phase 9 — Performance audit

| Metric | Value |
|--------|-------|
| `import zorksec.web.app` | ~389 ms |
| `zorksec version` (cold CLI) | ~0.4 s |
| Diagnostic full run | sub-second (this host) |

Repository health refresh is now backgrounded + cached (60-min TTL) so it never blocks startup or the UI.

---

## Phase 10 — Test audit

`pytest -q` → **179 passed** (0 failed) in ~49 s. Coverage spans CLI, web (incl. CSRF + Socket.IO auth), auth/recovery, executor (timeouts + verification + resource guard), diagnostics, SOC utils, task manager, offline mode, health cache, catalog, DB.

---

## Phase 11 — Auto-fixed defects (verified)

| # | Defect | Root cause | Fix | Re-test |
|---|--------|-----------|-----|---------|
| 1 | `report_service.py` annotated `-> Report` with `Report` never imported (F821) | annotation-only name not imported (module uses `from __future__ import annotations`, so latent not crashing) | added `if TYPE_CHECKING: from zorksec.db.models import Report` | ruff clean, 179 pass |
| 2 | 7 unused imports across 4 modules (F401) | dead imports left after refactors | removed | ruff clean, 179 pass |
| 3 | `tui/app.py` lambda assigned to a name (E731) | style/anti-pattern | rewrote as `def line_printer` | ruff clean, 179 pass |
| 4 | `tui/app.py` f-string without placeholder (F541) | leftover `f` prefix | removed prefix | ruff clean, 179 pass |

All fixes are low-risk (dead-code removal, annotation import, equivalent `def`) and were validated by the full suite.

---

## Phase 12 — Final validation

- ruff: All checks passed.
- pytest: 179 passed.
- import-all: 0 failures.
- WSGI HTTP smoke: all routes respond as expected.

---

## Operational note — "server hang" investigation

The earlier "smoke test ran for 20+ minutes" was **not** a code defect. Evidence:
- All candidate ports (8799/8800/8888/9000) were **free**; `ps` showed **no** server process.
- `socketio.run()` is a long-running server that never returns by design.
- The launches were issued as foreground/cancelled calls, so the tool waited on a process that intentionally does not exit.

Resolution: web validation is now done via the **non-blocking WSGI test client** (real HTTP codes above). No persistent server is left running.

---

## Remaining risks / recommended improvements (non-blocking)

1. **Repository health uses unauthenticated GitHub API** — rate-limited (60/hr). Recommend an optional `GITHUB_TOKEN`; current code already fails safe to `unknown`.
2. **25 tools have no detection binary** (multi-service platforms) — installed-state can be stale; documented limitation.
3. **Deep UI audit** (client-side JS errors, accessibility, mobile) not performed — recommended next.
4. **Diagnostic export** supports md/html/json/csv (no PDF).
5. **Larger v3.0 scope** (top-20-per-category catalog, login/dashboard visual redesign, first-login wizard UI) intentionally deferred to preserve architecture.
6. **Background-process tooling** in this environment could not be exercised (launch calls were cancelled); live-server load testing should be done in a normal shell.
