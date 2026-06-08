"""Tests for the Threat Intelligence workspace service."""

from __future__ import annotations

import pytest

from zorksec.db.session import init_db, session_scope
from zorksec.services.ti_service import (
    ThreatIntelService,
    classify_indicator,
    hash_kind,
)


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "ip"),
    ("2001:db8::1", "ip"),
    ("http://example.com/x", "url"),
    ("hxxp://evil[.]test/x", "url"),
    ("evil-example.test", "domain"),
    ("user@example.com", "email"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),
    ("", "unknown"),
    ("not a thing!!", "unknown"),
])
def test_classify_indicator(value, expected):
    assert classify_indicator(value) == expected


def test_hash_kind():
    assert hash_kind("44d88612fea8a8f36de82e1278abb02f") == "MD5"
    assert hash_kind("a" * 64) == "SHA256"
    assert hash_kind("notahash") is None


def test_seed_sample_feed_idempotent(zorksec_home):
    init_db()
    with session_scope() as s:
        first = ThreatIntelService(s).seed_sample_feed()
        assert first > 0
    with session_scope() as s:
        again = ThreatIntelService(s).seed_sample_feed()
        assert again == 0  # nothing new on re-seed


def test_dashboard_and_lookup(zorksec_home):
    init_db()
    with session_scope() as s:
        svc = ThreatIntelService(s)
        svc.seed_sample_feed()
    with session_scope() as s:
        svc = ThreatIntelService(s)
        dash = svc.dashboard()
        assert dash["counts"]  # has grouped counts
        assert len(dash["url"]) >= 1
        result = svc.lookup("203.0.113.45")
        assert result["type"] == "ip"
        assert result["known"] is True


def test_add_indicator_autoclassifies(zorksec_home):
    init_db()
    with session_scope() as s:
        svc = ThreatIntelService(s)
        svc.add_indicator("manual", "malware-host.test", "analyst note")
    with session_scope() as s:
        svc = ThreatIntelService(s)
        res = svc.lookup("malware-host.test")
        assert res["known"] is True
        assert res["type"] == "domain"
