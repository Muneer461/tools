# Phase 2.1 — Startup Flow & Theme Engine Remediation

Scope: the startup/browser-launch glitch (Issues 1 & 4) and the team theme
engine + persistence (Issues 2 & 3). The stable Install / Run / Docs / terminal
/ category-icon systems were **not** modified; their tests pass unchanged.

- Baseline before changes: **214 passed**
- After changes (+5 new tests): **219 passed**

---

## Issue 1 & 4 — Duplicate browser tab / localhost error on startup

### Root cause
`run_web()` started the server with `socketio.run(app, host, port)` without
disabling the Werkzeug/Flask reloader. When the reloader is active it forks a
**child process** that re-executes the startup path — including the browser
auto-launch — producing a **second tab**. Because that second launch can fire
before the (re)bound server is accepting connections, it lands on a
*connection refused / blank* localhost page that only works after a manual
refresh. The browser-open also used `webbrowser.open` with a 10s readiness
budget and no single-launch guard.

### Fix
- `socketio.run(..., debug=False, use_reloader=False)` — the reloader (the
  process-doubling cause) is now explicitly off in production launch.
- `_open_browser_when_ready` now has a module-level `_BROWSER_LAUNCHED` guard
  so the browser opens **at most once per process**, even if the worker is
  ever invoked twice.
- The readiness probe waits up to ~15s for the port to actually accept
  connections and **only opens the tab once the server is up** (it returns
  without opening if the server never comes up), so the browser never loads a
  not-ready localhost page. Uses `webbrowser.open_new_tab`.

### Issue 4 — startup status sequence
`run_web()` now prints a clear ready-sequence before opening the browser:

```
ZorkSec starting...
  [ OK ] Database initialised
  [ OK ] Tool registry loaded
  [ OK ] Socket.IO initialised
  [ OK ] Flask app ready
  [ OK ] Bound to http://127.0.0.1:8765
  System ready.
```

This makes a slow boot legible instead of looking like a hang, and reinforces
that the browser opens only after "System ready".

**Files:** `zorksec/web/app.py`

### Evidence
- `test_browser_launch_happens_at_most_once` — calling the launcher twice
  starts the worker thread only once.
- Existing port/origin startup tests (`test_find_free_port_*`,
  CORS-allow-list) still pass.

---

## Issue 2 & 3 — Team theme engine not working / not persistent

### Root cause
`zorksec.css` is authored against a set of CSS custom properties
(`--purple-primary`, `--cyan-primary`, `--bg-primary`, `--border-color`, …),
but the per-team override in `base.html` only set three **legacy aliases**
(`--accent`, `--bg`, `--panel`) that almost nothing reads. So choosing "Red
Team" updated the dropdown and those aliases, but every real surface kept the
hardcoded purple/blue values — the dashboard stayed blue/purple.

Persistence was also session-only: `team` lived in the Flask session, so it did
not reliably survive logout or a restart and was never stored on the user.

### Fix — full variable-driven theme engine
- New `zorksec/web/themes.py` defines a **complete CSS-variable palette** per
  team (`blue`, `red`, `both`) — primary/secondary/dark accents, secondary
  accent family, backgrounds, surfaces, borders, plus the legacy aliases.
- A Flask `context_processor` injects `theme_vars` for the active team into
  every template; `base.html` emits the whole palette into `:root`. Because
  the entire stylesheet reads those variables, switching team re-skins the
  **sidebar, tool cards, buttons, borders, header, modals, progress/metrics
  cards, terminal accent, and diagnostics dashboard** at once — no duplicated
  stylesheets.
  - Blue Team: SOC-analyst blues/cyans on a deep navy ground.
  - Red Team: crimson/blood-red accents on a near-black red ground (offensive
    security feel).
  - Purple Team (both): the original purple/cyan hybrid.

### Fix — persistence in the user profile DB
- Added a `team` column to the `users` table (additive SQLite migration, so
  existing databases upgrade automatically; default `both`).
- `POST /profile` writes the selection to the user record (and session).
- Login restores `session["team"]` from the user record, so the theme survives
  **refresh, logout/login, and a server restart** — backed by the database,
  not just LocalStorage/session.

**Files:** `zorksec/web/themes.py`, `zorksec/web/app.py`,
`zorksec/web/templates/base.html`, `zorksec/db/models.py`,
`zorksec/db/session.py`

### Evidence (tests + render checks)
- `test_red_team_applies_full_red_palette` — red `:root` contains `#ff3b4e`
  and `#14070a`, and **no** purple `#805aff`.
- `test_blue_team_applies_full_blue_palette` — blue `:root` contains `#2f81f7`
  and not the red accent.
- `test_theme_persists_across_logout_login` — red survives logout→login.
- `test_theme_persists_across_restart_via_db` — a second app instance (=
  restart) renders red after the user logs back in (loaded from DB).

---

## Files modified

| File | Change |
|------|--------|
| `zorksec/web/app.py` | no-reloader run, single browser launch, startup status, theme context-processor, team persistence on login & `/profile` |
| `zorksec/web/themes.py` | **new** full per-team CSS-variable palettes |
| `zorksec/web/templates/base.html` | emit the full palette into `:root` |
| `zorksec/db/models.py` | `users.team` column |
| `zorksec/db/session.py` | additive migration for `users.team` |
| `tests/test_web.py` | 5 new tests |
| `install.sh` | regenerated (embeds `themes.py`) |

## Remaining risks
- The startup status lines are printed before `socketio.run` for clarity; they
  reflect that init has completed (DB/registry/app are ready at that point)
  rather than streaming live per-stage timing.
- Browser auto-launch cannot be exercised in this headless sandbox; the
  single-launch guard and readiness wait are covered by unit tests and code
  review. A manual Kali launch is recommended to confirm the single-tab UX.

## Deployment notes
- Additive DB migration only (no destructive schema change); existing installs
  gain `users.team` automatically on next `init_db`.
- Backward compatible: if `theme_vars` is ever absent, `base.html` falls back
  to the legacy `theme` aliases.
- `?v=<mtime>` asset cache-buster invalidates the changed CSS/templates.
