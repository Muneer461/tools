"""Tests for the Help Center service (offline fallback + web search shape)."""

from __future__ import annotations

from zorksec.services import help_center_service as hc
from zorksec.services.help_center_service import HelpAnswer, HelpCenterService


def test_empty_query_is_handled():
    ans = HelpCenterService().ask("   ")
    assert isinstance(ans, HelpAnswer)
    assert "enter a question" in ans.answer.lower()


def test_offline_uses_local_kb(monkeypatch):
    monkeypatch.setattr(hc, "is_online", lambda timeout=3.0: False)
    ans = HelpCenterService().ask("tool shows command not found after install")
    assert ans.online is False
    assert ans.source == "offline"
    assert "PATH" in ans.answer


def test_offline_unknown_query_gives_safe_message(monkeypatch):
    monkeypatch.setattr(hc, "is_online", lambda timeout=3.0: False)
    ans = HelpCenterService().ask("completely unrelated astrophysics question")
    assert ans.online is False
    assert ans.answer  # non-empty, safe fallback


def test_online_web_results_are_returned(monkeypatch):
    monkeypatch.setattr(hc, "is_online", lambda timeout=3.0: True)
    monkeypatch.setattr(
        hc, "_search_web",
        lambda q: ("Sigma is a generic detection rule format.",
                   [{"title": "Sigma", "url": "https://example.org/sigma",
                     "snippet": "detection format"}]))
    ans = HelpCenterService().ask("what is a sigma rule")
    assert ans.source == "web"
    assert ans.online is True
    assert ans.results and ans.results[0]["url"].startswith("http")


def test_online_empty_search_falls_back_to_local(monkeypatch):
    monkeypatch.setattr(hc, "is_online", lambda timeout=3.0: True)
    monkeypatch.setattr(hc, "_search_web", lambda q: ("", []))
    ans = HelpCenterService().ask("dpkg broken apt lock")
    assert ans.source == "local"
    assert "dpkg" in ans.answer.lower() or "apt" in ans.answer.lower()
