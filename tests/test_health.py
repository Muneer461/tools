"""Tests for the pure repository-health scoring function."""

from __future__ import annotations

import datetime as _dt

from zorksec.services.health_service import score_repo


def _now():
    return _dt.datetime(2026, 1, 1)


def test_healthy_repo():
    data = {
        "archived": False,
        "stargazers_count": 5000,
        "pushed_at": "2025-12-01T00:00:00Z",
        "open_issues_count": 50,
    }
    result = score_repo(data, now=_now())
    assert result.status == "healthy"
    assert result.score >= 70


def test_archived_repo_is_deprecated():
    data = {
        "archived": True,
        "stargazers_count": 5000,
        "pushed_at": "2025-12-01T00:00:00Z",
    }
    result = score_repo(data, now=_now())
    assert result.status == "deprecated"
    assert result.archived is True


def test_stale_low_star_repo_warns_or_deprecates():
    data = {
        "archived": False,
        "stargazers_count": 10,
        "pushed_at": "2023-01-01T00:00:00Z",  # >1 year stale
        "open_issues_count": 5,
    }
    result = score_repo(data, now=_now())
    assert result.status in ("warning", "deprecated")
    assert result.score < 70


def test_missing_commit_date_penalised():
    data = {"archived": False, "stargazers_count": 1000}
    result = score_repo(data, now=_now())
    assert result.last_commit_at is None
    assert result.score <= 90



# ---------------------------------------------------------------------------
# Health cache (tool_health.json) + bulk refresh
# ---------------------------------------------------------------------------
import datetime as _dt

from zorksec.config import get_settings
from zorksec.services.health_service import (
    HealthResult,
    cache_is_fresh,
    load_health_cache,
    save_health_cache,
)


def test_health_cache_roundtrip_and_freshness(zorksec_home):
    settings = get_settings()
    assert cache_is_fresh(load_health_cache(settings)) is False  # no cache yet
    save_health_cache(settings, {"nmap": {"score": 90, "status": "healthy"}})
    cache = load_health_cache(settings)
    assert cache["tools"]["nmap"]["score"] == 90
    assert cache_is_fresh(cache) is True


def test_health_cache_stale_after_ttl(zorksec_home):
    settings = get_settings()
    save_health_cache(settings, {"x": {"score": 1}})
    cache = load_health_cache(settings)
    cache["updated_at"] = (_dt.datetime.utcnow() - _dt.timedelta(minutes=61)).isoformat()
    assert cache_is_fresh(cache) is False


def test_refresh_all_skips_when_cache_fresh(zorksec_home, monkeypatch):
    from zorksec.db.session import init_db, session_scope
    from zorksec.services.health_service import HealthService
    from zorksec.services.registry_service import RegistryService

    settings = get_settings()
    init_db(settings)
    with session_scope(settings) as db:
        RegistryService(db).seed_catalog()

    save_health_cache(settings, {"placeholder": {"score": 50}})  # fresh cache
    with session_scope(settings) as db:
        result = HealthService(db).refresh_all(settings, force=False)
    assert result["skipped"] is True


def test_refresh_all_force_uses_stubbed_check(zorksec_home, monkeypatch):
    from zorksec.db.session import init_db, session_scope
    from zorksec.services.health_service import HealthService
    from zorksec.services.registry_service import RegistryService

    settings = get_settings()
    init_db(settings)
    with session_scope(settings) as db:
        RegistryService(db).seed_catalog()

    # Avoid network: stub check_repo so refresh is deterministic + fast.
    healthy = HealthResult(88, "healthy", 1000, False, None, None, "ok")
    monkeypatch.setattr(HealthService, "check_repo", lambda self, repo: healthy)

    with session_scope(settings) as db:
        result = HealthService(db).refresh_all(settings, force=True, limit=3)
    assert result["skipped"] is False
    assert result["refreshed"] >= 1
    cache = load_health_cache(settings)
    assert cache["tools"]
