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
