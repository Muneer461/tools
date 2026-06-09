"""Repository health engine.

Scores a GitHub project 0-100 from signals that matter for "is this tool
safe/maintained to install": archived flag, commit recency, release activity,
and popularity. The scoring function is pure and unit-tested; network access
is isolated in :meth:`check_repo` and fails safe (status ``unknown``) when
offline or rate-limited.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from zorksec.config import Settings, get_settings
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

GITHUB_API = "https://api.github.com/repos/{repo}"
HEALTH_CACHE_TTL_MINUTES = 60


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

    # ----- bulk / cached refresh -------------------------------------------
    def refresh_all(self, settings: Settings | None = None,
                    force: bool = False, limit: int | None = None) -> dict:
        """Refresh health for every catalog tool that has a GitHub repo.

        Results are persisted to the DB *and* a JSON cache. When ``force`` is
        False and the cache is still fresh (< 60 min), the refresh is skipped so
        the UI is not blocked and the GitHub API is not hammered.
        """
        settings = settings or get_settings()
        cache = load_health_cache(settings)
        if not force and cache_is_fresh(cache):
            logger.info("Health cache fresh; skipping refresh")
            return {"refreshed": 0, "skipped": True,
                    "cached": len(cache.get("tools", {}))}

        from zorksec.registry.catalog import CATALOG

        repos = [(d.slug, d.github) for d in CATALOG if d.github]
        if limit is not None:
            repos = repos[:limit]
        tools_cache: dict[str, dict] = {}
        refreshed = 0
        for slug, _repo in repos:
            result = self.refresh_tool(slug)
            if result is None:
                continue
            refreshed += 1
            tools_cache[slug] = {
                "score": result.score,
                "status": result.status,
                "stars": result.stars,
                "archived": result.archived,
            }
        save_health_cache(settings, tools_cache)
        logger.info("Health refresh complete: %d tools scored", refreshed)
        return {"refreshed": refreshed, "skipped": False, "cached": len(tools_cache)}


# ---------------------------------------------------------------------------
# Cache helpers (tool_health.json) + background refresh
# ---------------------------------------------------------------------------
def health_cache_path(settings: Settings) -> Path:
    """Location of the persisted health cache."""
    return settings.home / "tool_health.json"


def load_health_cache(settings: Settings) -> dict:
    """Load the health cache ({'updated_at':iso, 'tools':{slug:{...}}})."""
    try:
        return json.loads(health_cache_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_health_cache(settings: Settings, tools: dict) -> dict:
    """Persist the health cache with a fresh timestamp; returns the written doc."""
    doc = {"updated_at": _dt.datetime.utcnow().isoformat(timespec="seconds"),
           "tools": tools}
    path = health_cache_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def cache_is_fresh(cache: dict, ttl_minutes: int = HEALTH_CACHE_TTL_MINUTES) -> bool:
    """True if the cache has a timestamp newer than ``ttl_minutes`` ago."""
    updated = cache.get("updated_at")
    if not updated:
        return False
    try:
        ts = _dt.datetime.fromisoformat(updated)
    except ValueError:
        return False
    age = _dt.datetime.utcnow() - ts
    return age < _dt.timedelta(minutes=ttl_minutes)


def start_background_refresh(settings: Settings | None = None,
                             force: bool = False) -> threading.Thread:
    """Refresh repository health on a daemon thread so startup never blocks.

    Opens its own DB session (SQLAlchemy sessions are not thread-safe) and
    fails safe: any error is logged and the thread exits quietly.
    """
    settings = settings or get_settings()

    def _worker() -> None:
        try:
            from zorksec.db.session import session_scope

            with session_scope(settings) as session:
                HealthService(session).refresh_all(settings, force=force)
        except Exception as exc:  # pragma: no cover - background safety
            logger.warning("Background health refresh failed: %s", exc)

    thread = threading.Thread(target=_worker, name="health-refresh", daemon=True)
    thread.start()
    return thread
