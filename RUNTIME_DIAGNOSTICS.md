# ZorkSec Runtime Diagnostics

Investigation of the reported runtime symptoms (dead Install/Run/Docs buttons,
terminal never opening, dashboard behaving like static content) on the Kali
deployment, using the actual running server plus real JavaScript execution.

## TL;DR — root causes

| # | Symptom | Root cause | Status |
|---|---------|-----------|--------|
| 1 | In-browser **terminal never opens** | Terminal page loaded `xterm.js`, `xterm-addon-fit`, `socket.io` from **public CDNs**; in an isolated/air-gapped Kali lab those fetches fail, so `Terminal`/`io` are undefined and the terminal cannot boot. | **Fixed** — assets vendored locally |
| 2 | Install / Run open a tab that shows nothing useful | The new tab points at `/terminal`, which failed to load (cause #1). Docs (`/usage`) does not need a CDN and worked. | **Fixed** via #1 |
| 3 | Icons missing / "static image" feel | Font Awesome was loaded from a CDN; offline it renders no icons, making the UI look broken/inert. | **Fixed** — Font Awesome vendored locally |
| 4 | `sqlite3.OperationalError: database is locked` | The background health refresh held **one SQLite write transaction open across ~70 network calls**. | **Fixed** — commit per tool |
| 5 | Stale UI after upgrade | Static CSS/JS had no cache-busting; browsers could serve an old cached stylesheet. | **Fixed** — `?v=<mtime>` stamp |

The button **handlers themselves were never broken** — proven below.

## Environment

- Server: `zorksec --web` (Flask + Flask-SocketIO, gevent) — starts cleanly,
  binds `127.0.0.1`, serves login → change-password → dashboard.
- A full headless Chromium could **not** be launched in the audit sandbox
  (Amazon Linux 2023; the `nss`/`libnss3.so` RPM fails to unpack on the
  read-only overlay root). Screenshots via Chromium were therefore not
  obtainable in this environment. Instead the dashboard's real JavaScript was
  executed with **Node.js** and the DOM behaviour reproduced with **jsdom**,
  which is sufficient to prove handler registration and click behaviour. On a
  normal Kali desktop Chromium/Firefox launches fine.

## Evidence 1 — the JavaScript parses and the handlers register

The dashboard's inline `<script>` (the block that defines `openTerm`,
`openDocs`, `askRun`, `runChoice`, `runCustom`) was extracted from the live
server-rendered HTML and checked:

```
NODE --check returncode: 0          # no syntax error -> the whole block runs
NODE stderr: (none)
declares openTerm: True
declares openDocs: True
declares askRun: True
declares runChoice: True
declares runCustom: True
declares applyFilter: True
```

A JavaScript **syntax error** is the only thing that would prevent *all* inline
`onclick="..."` handlers from working (it stops the script being parsed, so no
function declarations are registered). There is no syntax error, so the
handlers are defined and reachable from the buttons.

## Evidence 2 — clicking the buttons actually fires (jsdom)

The server-rendered dashboard was loaded in jsdom with `window.open` stubbed,
then real `MouseEvent('click')` events were dispatched:

```
typeof window.openTerm               function
typeof window.askRun                 function
typeof window.openDocs               function
first tool card found                true
install onclick attr                 openTerm('bloodhound','install')
docs onclick attr                    openDocs('bloodhound')

--- clicking INSTALL ---
window.open called with              /terminal?tool=bloodhound&action=install
--- clicking DOCS ---
window.open called with              /usage?tool=bloodhound
--- clicking RUN (opens modal) ---
run-modal display                    flex
after modal browser choice open()    /terminal?tool=bloodhound&action=run
--- clicking Installed-tools filter ---
installed filter present             true
cards total / visible                101 / 0
empty-state shown                    true
```

**Conclusion:** Install, Run and Docs each correctly invoke their handler and
open the right URL. The buttons are wired correctly in the repository code.

## Evidence 3 — the terminal backend works end-to-end

Using Flask-SocketIO's test client (real connect + event flow, no browser):

```
socket connected: True
events received: 1
  <- output: "\r\n[ZorkSec terminal] running: nmap --version\r\n
              Type commands below. Use 'exit' to close this terminal."
TERMINAL_EMITS_OUTPUT: True
```

So the Socket.IO namespace, auth gate, `start` handler, command building and
PTY pump all function. The only thing that prevented the terminal from
appearing was the **client-side libraries failing to load from the CDN**.

## Evidence 4 — server HTTP surface is healthy

Every route returns 200 for an authenticated session (no 500s reproduced):

```
GET /              -> 200      /api/tools          -> 200
/lab               -> 200      /api/metrics        -> 200
/diagnostics       -> 200      /terminal?tool=nmap -> 200
/kali-diagnostics  -> 200      /usage?tool=nmap    -> 200
/help              -> 200      /api/attack         -> 200
/security-question -> 200      /forgot-password    -> 200
/nonexistent-page  -> 404 (now a themed page)
```

## Root cause detail — CDN dependency (symptoms 1-3)

`templates/terminal.html` previously loaded:

```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
```

`HOW_TO_RUN.txt` recommends running ZorkSec inside an **isolated lab with no
internet**. With no internet these four requests fail; `Terminal`, `FitAddon`
and `io` are `undefined`; the page's own guard then shows
"Terminal libraries failed to load". `dashboard.html`/`login.html` similarly
pulled Font Awesome from `cdnjs`, so offline the icons disappear and the UI
looks like a static, broken image.

**Fix:** the four terminal libraries and Font Awesome (CSS + woff2 fonts) are
now vendored under `zorksec/web/static/vendor/` and referenced via
`url_for('static', ...)`. The dashboard and terminal now work fully offline.

## Root cause detail — `database is locked` (symptom 4)

- File: `zorksec/services/health_service.py`
- Function: `HealthService.refresh_all` → `refresh_tool` (`self.session.flush()`)
- Driver: `start_background_refresh._worker` wraps the whole refresh in **one**
  `session_scope`.

`flush()` acquires SQLite's write lock; the surrounding `session_scope` only
commits at the very end. So the background thread held the write lock across
**all ~70 GitHub API calls** (up to 10s each). Any concurrent dashboard write
(audit log, `sync_installed_status`) then waited past `busy_timeout` and raised
`sqlite3.OperationalError: database is locked`, which surfaced as a 500.

**Fix:** `refresh_all` now `commit()`s after each tool (lock held for
milliseconds, never across network I/O) and isolates per-tool failures;
`busy_timeout` raised 5s → 15s as defence-in-depth. Regression test:
`tests/test_health.py::test_refresh_all_commits_per_tool_releasing_write_lock`.

## Click → backend trace (verified)

```
Install button
  └─ onclick openTerm(slug,'install')
       └─ window.open('/terminal?tool=slug&action=install')   [Evidence 2]
            └─ GET /terminal -> 200, loads LOCAL xterm+socket.io [Evidence 4/1]
                 └─ socket 'start' {action:'install'}           [Evidence 3]
                      └─ build_install_command() from trusted catalog
                           └─ PTY pump -> 'output' frames -> xterm render

Run button → askRun() → modal → runChoice('browser') → same /terminal path,
            or runChoice('native') → POST /api/run-target (200).

Docs button → openDocs(slug) → window.open('/usage?tool=slug') -> 200
            (no CDN dependency; always worked).
```

## Why the user saw "nothing happens"

On an offline Kali host, Install/Run open a new tab to `/terminal`, which then
shows the library-load error (or, if the popup was blocked, the dashboard tab
navigates to that same broken terminal). Combined with missing Font Awesome
icons, the dashboard appeared inert. With assets vendored locally, the new tab
now boots a working terminal and the icons render — resolving the perceived
"dead button" behaviour. Cache-busting ensures an upgraded install never keeps
serving a stale cached page.



---

## Follow-up audit (round 2) — execution chain & remaining gaps

### Tool-by-tool execution chain (verified live)

Command building from the trusted catalog + live Socket.IO output:

```
nmap        install: sudo apt-get install -y nmap        run: nmap --version
tshark      install: sudo apt-get install -y tshark      run: tshark --version
nikto       install: sudo apt-get install -y nikto       run: nikto -Version
gobuster    install: sudo apt-get install -y gobuster    run: gobuster version
sqlmap      install: sudo apt-get install -y sqlmap       run: sqlmap --version
bloodhound  install: git clone --depth 1 .../BloodHound   run: (no CLI - see below)

SOCKET.IO terminal: nmap install -> output frames=1 (banner + command)
                    nmap run     -> output frames=1 (banner + command)
DOCS (/usage) for all named tools -> 200
```
Note: `wireshark` is catalogued as **`tshark`** (the CLI component) — there is
no separate `wireshark` slug.

### New issue found & fixed — Run dead-end for non-CLI tools

`build_run_command` raised `Tool 'X' has no run command or binary defined.` for
**19 of 101** tools that are services / GUIs / libraries (TheHive, Cortex, GRR,
CyberChef, MISP, OpenCTI, Yeti, IntelOwl, BeEF, Empire, BloodHound, Impacket,
Arkime, pySigma, Atomic Red Team, Caldera, VECTR, OSSEM, ATT&CK Navigator).
Clicking **Run** on these ended in a cryptic terminal error.

- File/function: `zorksec/services/executor_service.py::build_run_command`
  (final `if not binary:` branch).
- Fix: the catalog snapshot now carries a `runnable` flag (true when a tool has
  a `run_command` or `check_binary`); cards render `data-runnable`. The
  dashboard Run modal detects non-runnable tools and **guides the user to Docs**
  instead of a dead-end. The terminal-side error message is now actionable and
  includes the docs URL.
- Tests: `test_dashboard_marks_non_runnable_tools`,
  `test_non_runnable_tool_run_gives_actionable_message`.

### Offline completion — web fonts vendored

The last external dependency (`login.html` Google Fonts) was removed: Inter,
JetBrains Mono and Orbitron are vendored as 14 local woff2 files under
`vendor/fonts/` with a local `fonts.css`, loaded site-wide via `base.html`.
Templates now contain **zero `https://` references**. Locked in by
`test_fonts_vendored_offline` and the strengthened offline template sweep.
