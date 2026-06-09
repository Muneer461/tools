"""Tests for offline mode + PENDING_ACTIONS.md queue/replay."""

from __future__ import annotations

from zorksec.services.offline_service import (
    INSTALL,
    OfflineService,
    PendingAction,
    is_online,
)


def test_is_online_returns_bool():
    assert isinstance(is_online(timeout=2), bool)


def test_queue_and_dedupe(zorksec_home):
    svc = OfflineService()
    svc.queue_action("Nmap", "sudo apt-get install -y nmap", INSTALL)
    svc.queue_action("Subfinder", "go install subfinder", INSTALL)
    svc.queue_action("Nmap", "sudo apt-get install -y nmap", INSTALL)  # duplicate
    pending = svc.pending_actions()
    assert len(pending) == 2
    assert {p.name for p in pending} == {"Nmap", "Subfinder"}


def test_markdown_is_rendered(zorksec_home):
    svc = OfflineService()
    svc.queue_action("Nmap", "sudo apt-get install -y nmap", INSTALL)
    text = svc.markdown_path.read_text(encoding="utf-8")
    assert "# ZorkSec Pending Actions" in text
    assert "Pending Installs" in text
    assert "Nmap" in text


def test_process_pending_with_retries(zorksec_home):
    svc = OfflineService()
    svc.queue_action("Good", "ok", INSTALL)
    svc.queue_action("Bad", "boom", INSTALL)

    def runner(action: PendingAction) -> int:
        return 0 if action.name == "Good" else 1

    result = svc.process_pending(runner)
    assert result["done"] == 1
    assert result["failed"] == 1
    assert result["remaining"] == 0  # FAILED is no longer "pending"
    # The bad action was retried up to the max.
    from zorksec.services.offline_service import MAX_RETRIES
    bad = next(a for a in svc._load() if a.name == "Bad")
    assert bad.attempts == MAX_RETRIES
    assert bad.state == "FAILED"


def test_clear(zorksec_home):
    svc = OfflineService()
    svc.queue_action("X", "cmd", INSTALL)
    svc.clear()
    assert svc.pending_actions() == []
