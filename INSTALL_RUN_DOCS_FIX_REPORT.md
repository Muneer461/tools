# Install / Run / Docs Button Failure — Root Cause Analysis & Fix

## Executive summary

The dashboard's **Install**, **Run**, and **Docs** buttons did nothing when
clicked: no network request, no Socket.IO event, no backend route hit, no
terminal activity, and — tellingly — **no JavaScript console error**. Every
other delegated action on the page (sidebar category filters, the lab command
runner, the AI "Ask" button, the mobile sidebar toggle) worked normally.

That precise symptom pattern — *only the tool-card buttons fail, silently* —
pointed to a CSS click-interception bug rather than a JavaScript or backend
fault. The root cause was a decorative pseudo-element overlay
(`.tool-card::before`) that covered every card and swallowed the clicks before
they could reach the buttons.

This was fixed with a one-line-class CSS change (`pointer-events: none` on the
decorative overlay), hardened with an explicit stacking order, and the same
defensive treatment was applied to the other decorative pseudo-elements.

## Root cause

`zorksec/web/static/zorksec.css` defined a hover-glow overlay on each tool card:

```css
.tool-card { position: relative; overflow: hidden; }
.tool-card::before {
  content: '';
  position: absolute;
  inset: 0;                 /* covers the ENTIRE card, including the buttons */
  background: radial-gradient(...);
  opacity: 0;               /* invisible, but NOT non-interactive */
  transition: opacity 0.3s;
}
.tool-card:hover::before { opacity: 1; }
```

Two CSS facts combine to produce the bug:

1. **An absolutely-positioned pseudo-element paints above its statically
   positioned siblings.** The `.tool-actions` buttons have no `position`/
   `z-index`, so within the card's stacking context the `::before` overlay sits
   on top of them.
2. **`opacity: 0` does *not* disable pointer events.** Unlike `display:none` or
   `visibility:hidden`, a fully transparent element still participates in
   hit-testing. So the overlay intercepts clicks at all times, not just on
   hover.

When a user clicks the Install button, the browser hit-test resolves to the
`::before` pseudo-element. The event is dispatched with
`event.target` = the host `.tool-card` element. The delegated handler in
`dashboard.js` then runs:

```js
const el = ev.target.closest("[data-action]");
if (!el) return;   // <-- returns here
```

`closest()` walks **up** the ancestor chain. The `.tool-card` has no
`data-action`, and none of its ancestors do either, so `closest()` returns
`null` and the handler exits silently. No action, no request, no error — exactly
the reported behaviour.

This also explains why the other buttons worked: the sidebar nav items, the lab
runner, the AI button and the modal buttons are **not** underneath a
`.tool-card::before` overlay, so their clicks reach the real target.

## The fix

File: `zorksec/web/static/zorksec.css`

```css
.tool-card::before {
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;   /* decorative overlay must never capture clicks */
  z-index: 0;
  background: radial-gradient(...);
  opacity: 0;
  transition: opacity 0.3s;
}
/* Real card content sits above the decorative overlay as a belt-and-braces
   guarantee even if pointer-events support were ever lost. */
.tool-card > * { position: relative; z-index: 1; }
```

The same `pointer-events: none` hardening was applied to the other purely
decorative pseudo-elements so this class of regression cannot recur:

- `.stat-card::after` (corner glow)
- `.sidebar-profile .profile-avatar::after` (status dot)
- `.nav-item.active::before` (active-tab accent bar)

`dashboard.js` was intentionally left unchanged: its event-delegation logic was
already correct. The defect was entirely in CSS hit-testing.

Because `install.sh` embeds a base64 snapshot of every source file (verified by
`tests/test_installer.py`), it was regenerated with `python build_installer.py`
so the shipped installer carries the fixed stylesheet.

## Runtime evidence

### Backend execution chain (Flask test client against the real app)

The exact routes the three buttons drive were exercised end-to-end after a real
login + forced password-change + recovery-question setup:

| Step | Result |
|------|--------|
| `POST /login` (default creds) | `302 → /` |
| `POST /change-password` (+ recovery question) | `302 → /` |
| `GET /` (dashboard) | `200`, **101 tool cards** rendered |
| `data-action="tool-install"` present in HTML | yes |
| `data-action="tool-run"` present in HTML | yes |
| `data-action="tool-docs"` present in HTML | yes |
| `dashboard.js` loaded | yes |
| `GET /terminal?tool=<slug>&action=install` (Install target) | `200`, includes `socket.io` |
| `GET /terminal?tool=<slug>&action=run` (Run → browser terminal) | `200` |
| `GET /usage?tool=<slug>` (Docs target) | `200` |
| `GET /api/metrics` | `200` |

### Test suite

`python -m pytest` → **214 passed** (after regenerating `install.sh`).

## Known related finding (not blocking Install/Run/Docs)

`POST /api/run-target` (the *native* Kali-terminal run option) returned `400`
for the `bloodhound` catalog entry: *"Tool 'bloodhound' has no run command or
binary defined."* The default **in-browser** Run path (`/terminal`) is
unaffected and works. This is a catalog-completeness gap (Phase 6) worth a
follow-up pass across all entries that lack a run command/binary.

## Honest scope note

This environment is a generic Linux sandbox, **not** a Kali Linux desktop, and
has no GUI browser. The evidence above is real route-level runtime evidence and
a static + dynamic analysis of the CSS hit-testing behaviour. The
`pointer-events`/stacking fix is standard, well-defined browser behaviour, but a
final click-through in a real Kali browser is still recommended as the last
confirmation before sign-off.


---

## Real-browser proof (Chromium via Playwright)

The previous section relied on route-level evidence and CSS analysis. To satisfy
the Phase 3/4/5 requirement for genuine browser hit-testing, the rendered
dashboard (real `zorksec.css` + `dashboard.js`) was loaded in **real Chromium**
(Playwright `chromium`, Blink engine) and probed with `document.elementFromPoint`
and real mouse clicks.

> Note on the sandbox: this is a generic Linux image, not Kali, and Chromium's
> shared-library deps (`libnss3`, `libnspr4`, ...) were not present. They were
> installed/extracted (`dnf` + `rpm2archive`) and supplied via `LD_LIBRARY_PATH`.
> The browser engine doing the layout and hit-testing is real Chromium/Blink.

### After the fix (current code)

| Probe | Result |
|-------|--------|
| `elementFromPoint(centre of Install button)` | `BUTTON.tool-btn install`, `data-action="tool-install"`, `hitsButton:true` |
| `elementFromPoint(centre of Run button)` | `BUTTON.tool-btn run`, `data-action="tool-run"`, `hitsButton:true` |
| `elementFromPoint(centre of Docs button)` | `BUTTON.tool-btn docs`, `data-action="tool-docs"`, `hitsButton:true` |
| real click **Install** | `window.open("/terminal?tool=bloodhound&action=install")` |
| real click **Docs** | `window.open("/usage?tool=bloodhound")` |
| real click **Run** | run-modal computed `display: flex` (modal opens) |
| console / page errors | none |

These are exactly the URL formats required by Phase 5
(`/terminal?tool=...&action=install`, `/terminal?tool=...&action=run` via the
modal's "browser terminal" choice, and `/usage?tool=...`).

### Regression reproduction (overlay re-enabled)

Re-enabling `pointer-events` on `.tool-card::before` (reverting the fix) in the
same real browser:

| Probe | Result |
|-------|--------|
| `elementFromPoint(centre of Install button)` | `DIV.tool-card` (the overlay host), `hitsButton:false` |
| real click on that pixel | `window.open` called **0 times** — nothing happens, no error |

This reproduces the originally reported defect precisely and confirms the fix is
both necessary and sufficient.

---

## Phase 8 — Category icon modernization

Every catalog category previously rendered with the same generic
`fa-folder` glyph in the sidebar, and every tool card used a generic
`fa-shield-halved` logo. Both now use a distinctive, category-appropriate icon
from the single icon library already bundled with the app (Font Awesome Free
**6.5.1**).

**Implementation**
- New module `zorksec/web/category_icons.py` maps each of the **23** catalog
  categories (plus canonical-name aliases) to a verified FA6 Free icon, with a
  non-folder default (`fa-folder-tree`) for any unmapped value.
- Registered as a Jinja global (`category_icon`) in `create_app` (`app.py`).
- `dashboard.html`: sidebar category buttons and tool-card logos now call
  `category_icon(...)`.

**Mapping (catalog categories)**

| Category | Icon | | Category | Icon |
|---|---|---|---|---|
| Information Gathering | `fa-magnifying-glass` | | Threat Intelligence | `fa-brain` |
| Network Monitoring | `fa-satellite-dish` | | Vulnerability Scanning | `fa-bug` |
| Web Application | `fa-globe` | | Reverse Engineering | `fa-gears` |
| OSINT for SOC | `fa-user-secret` | | Detection Engineering | `fa-binoculars` |
| Social Media OSINT | `fa-share-nodes` | | SOC Utilities | `fa-toolbox` |
| Malware Analysis | `fa-virus` | | Log Analysis | `fa-file-lines` |
| Forensics / DFIR | `fa-microscope` | | SIEM / Logging | `fa-gauge-high` |
| Threat Hunting | `fa-crosshairs` | | Phishing Analysis | `fa-envelope-open-text` |
| Incident Response | `fa-triangle-exclamation` | | Post Exploitation | `fa-skull` |
| Wireless Security | `fa-wifi` | | Active Directory | `fa-building` |
| Password Auditing | `fa-key` | | Exploitation | `fa-bolt` |
| Other | `fa-shapes` | | | |

**Verification**
- All icon classes confirmed present in the vendored `all.min.css`.
- Rendered dashboard HTML: **0** category nav buttons use `fa-folder`; all 101
  tool-card logos use a category-specific icon (0 generic shields remain).
- Real Chromium: the Font Awesome webfont loads (`font-family: "Font Awesome 6
  Free"`) and the glyphs paint; a full-page screenshot was captured as visual
  evidence (`_verify/dashboard_icons.png`).
- The click hit-test was re-run after the template/icon changes — Install/Run/
  Docs still hit-test to their buttons and generate the correct URLs (no
  regression from the icon work).
