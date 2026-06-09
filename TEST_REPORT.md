# ZorkSec Test Report

Toolchain run on the audit branch (`audit/ui-hardening-login-enforcement`),
Python 3.11, isolated `ZORKSEC_HOME`.

## Summary

| Tool | Result |
|------|--------|
| `pytest` | **217 passed** |
| `ruff check zorksec/` | **clean** (All checks passed) |
| `pip-audit` | **no known vulnerabilities** |
| `bandit -r zorksec/` | 3 High + 5 Medium — all intentional `shell=True` (see below) |
| `mypy zorksec/` | 10 notes/errors in 8 files — pre-existing (missing third-party stubs + loose typing); none introduced by this work |

## pytest

217 tests pass, covering: auth (login, forced wizard, CSRF, recovery lockout),
crypto, catalog, discovery, dependency, health (incl. the DB-lock regression),
executor, report, diagnostics, Kali diagnostics, SOC utils, TI, DFIR, detection,
TUI, and the web layer.

Web/security highlights added during this audit:
- `test_every_route_requires_authentication` — auto-enumerates the URL map;
  every non-public route blocks logged-out access.
- `test_tools_blocked_until_wizard_complete` — tools unreachable until the
  first-login wizard finishes.
- `test_default_password_rejected_after_change`.
- `test_dashboard_uses_external_js_and_delegation` / `..._kali_..._external_js` /
  `test_diagnostic_center_uses_external_js` — assert no inline `onclick`.
- `test_terminal_assets_served_locally_not_cdn`, `test_fonts_vendored_offline`,
  `test_frontend_assets_are_vendored_offline` — offline guarantees.
- `test_committed_install_sh_is_in_sync_with_source` — installer never drifts.
- `test_dashboard_marks_non_runnable_tools`,
  `test_non_runnable_tool_run_gives_actionable_message` — Run UX for non-CLI tools.
- `test_refresh_all_commits_per_tool_releasing_write_lock` — DB-lock fix.

## bandit (accepted-by-design)

All High/Medium findings are `subprocess(..., shell=True)` in the **tool
launcher** (`executor_service`, `task_manager`, `web/terminal.py`, `web/app.py`).
This is intrinsic to a security-tool runner: commands are built from the
**trusted catalog**, not from raw network input; the free-form lab runner is
explicitly flagged and **audit-logged**; execution requires an authenticated,
fully-provisioned session. These are documented intentional risks, not defects.

## pip-audit

`No known vulnerabilities found` for the dependency set (the local `zorksec`
package itself is correctly skipped as not-on-PyPI).

## mypy

Pre-existing only: missing stubs for `flask_socketio`, `reportlab`, `docx`, and
a few loosely-typed call sites in `catalog.py`, `usage_service.py`,
`kali_diagnostics_service.py`, `soc_utils_service.py`, `web/terminal.py`. None
are in code changed by this audit. Recommended as a separate typing pass.
