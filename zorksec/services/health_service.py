"""Repository health engine.

Scores a GitHub project 0-100 from signals that matter for "is this tool
safe/maintained to install": archived flag, commit recency, release activity,
and popularity. The scoring function is pure and unit-tested; network access
is isolated in :meth:`check_repo` and fails safe (status ``unknown``) when
offline or rate-limited.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from sqlalchemy.orm import Session

from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

GITHUB_API = "https://api.github.com/repos/{repo}"


@dataclass
class HealthResult:
    score: int
    status: str  # healthy | warning | deprecated | unknown
    stars: int
    archived: bool
    last_commit_at: _dt.datetime | None
    last_release: str | None
    reason: str


def _parse_iso(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    try:
        return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def score_repo(data: dict, now: _dt.datetime | None = None) -> HealthResult:
    """Pure scoring from a GitHub repo API payload (dict).

    Start at 100 and subtract penalties; clamp to 0-100. Status thresholds:
    archived or score < 40 -> deprecated; score < 70 -> warning; else healthy.
    """
    now = now or _dt.datetime.utcnow()
    score = 100
    reasons: list[str] = []

    archived = bool(data.get("archived"))
    if archived:
        score -= 50
        reasons.append("archived")

    stars = int(data.get("stargazers_count", 0) or 0)
    if stars < 50:
        score -= 15
        reasons.append("few stars")
    elif stars < 500:
        score -= 5

    last_commit = _parse_iso(data.get("pushed_at"))
    if last_commit is None:
        score -= 10
        reasons.append("no commit date")
    else:
        days = (now - last_commit).days
        if days > 365:
            score -= 30
            reasons.append("stale (>1y)")
        elif days > 180:
            score -= 15
            reasons.append("aging (>6m)")

    open_issues = int(data.get("open_issues_count", 0) or 0)
    if open_issues > 1000:
        score -= 5
        reasons.append("many open issues")

    score = max(0, min(100, score))
    if archived or score < 40:
        status = "deprecated"
    elif score < 70:
        status = "warning"
    else:
        status = "healthy"

    return HealthResult(
        score=score,
        status=status,
        stars=stars,
        archived=archived,
        last_commit_at=last_commit,
        last_release=None,
        reason=", ".join(reasons) or "ok",
    )


class HealthService:
    def __init__(self, session: Session, timeout: int = 10) -> None:
        self.session = session
        self.tools = ToolRepository(session)
        self.timeout = timeout

    def check_repo(self, repo: str) -> HealthResult:
        """Fetch and score a 'owner/name' repo. Fails safe when offline."""
        try:
            import requests  # imported lazily so offline installs still work
        except ImportError:
            return self._unknown("requests not installed")

        try:
            resp = requests.get(
                GITHUB_API.format(repo=repo),
                timeout=self.timeout,
                headers={"Accept": "application/vnd.github+json"},
            )
        except Exception as exc:  # network failure, DNS, etc.
            logger.warning("Health check network error for %s: %s", repo, exc)
            return self._unknown("network error")

        if resp.status_code == 404:
            return HealthResult(0, "deprecated", 0, False, None, None, "repository not found")
        if resp.status_code != 200:
            return self._unknown(f"http {resp.status_code}")

        try:
            return score_repo(resp.json())
        except ValueError:
            return self._unknown("bad response")

    def refresh_tool(self, slug: str) -> HealthResult | None:
        """Refresh and persist health for a single catalog tool with a repo."""
        from zorksec.registry.catalog import CATALOG

        repo_by_slug = {d.slug: d.github for d in CATALOG}
        repo = repo_by_slug.get(slug, "")
        tool = self.tools.get_by_slug(slug)
        if tool is None or not repo:
            return None
        result = self.check_repo(repo)
        health = self.tools.ensure_health(tool)
        health.score = result.score
        health.status = result.status
        health.stars = result.stars
        health.archived = result.archived
        health.last_commit_at = result.last_commit_at
        health.checked_at = _dt.datetime.utcnow()
        self.session.flush()
        return result

    @staticmethod
    def _unknown(reason: str) -> HealthResult:
        return HealthResult(0, "unknown", 0, False, None, None, reason)
