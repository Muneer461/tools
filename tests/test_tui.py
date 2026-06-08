"""Smoke tests for the TUI rendering (no interactive input loop)."""

from __future__ import annotations

import io

from rich.console import Console

from zorksec.tui.app import TuiApp
from zorksec.tui.banner import render_banner_text


def _capture_console() -> Console:
    return Console(file=io.StringIO(), width=120, force_terminal=False)


def test_banner_contains_branding():
    text = render_banner_text()
    assert "ZorkSec" in text
    assert "SOC" in text


def test_app_bootstrap_loads_tools(zorksec_home):
    app = TuiApp(team="blue", console=_capture_console())
    app.bootstrap()
    assert len(app._rows) > 0
    assert all(r.team in ("blue", "both") for r in app._rows)


def test_categories_grouping(zorksec_home):
    app = TuiApp(team="both", console=_capture_console())
    app.bootstrap()
    cats = app.categories()
    assert len(cats) > 5
    total = sum(len(v) for v in cats.values())
    assert total == len(app._rows)


def test_search_and_recommend(zorksec_home):
    app = TuiApp(team="both", console=_capture_console())
    app.bootstrap()
    assert any(r.slug == "nmap" for r in app.search("nmap"))
    assert app.search("zzzz-nope") == []
    rec = app.recommended()
    assert any(r.slug == "nmap" for r in rec)


def test_render_methods_do_not_raise(zorksec_home):
    console = _capture_console()
    app = TuiApp(team="blue", console=console)
    app.bootstrap()
    console.print(app.banner_panel())
    console.print(app.main_menu_renderable())
    first_cat = next(iter(app.categories().keys()))
    console.print(app.category_table(first_cat))
    console.print(app.tool_panel(app._rows[0]))
    output = console.file.getvalue()
    assert len(output) > 0
