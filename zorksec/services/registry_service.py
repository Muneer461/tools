"""Registry service: seed the catalog into the DB and query it.

Seeding is idempotent - it upserts each :class:`ToolDef` by slug, so it can be
re-run after catalog updates without creating duplicates.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import MitreMapping, ToolRegistry
from zorksec.registry.catalog import CATALOG, ToolDef, catalog_by_team, categories
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ToolRow:
    """A flat, session-independent snapshot of a catalog tool for the UI."""

    slug: str
    name: str
    description: str
    category: str
    team: str
    beginner_note: str
    install_method: str
    docs_url: str
    license: str
    requires_isolation: bool
    installed: bool
    health_status: str
    health_score: int
    runnable: bool = True


class RegistryService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.tools = ToolRepository(session)

    # ----- seeding ----------------------------------------------------------
    def seed_catalog(self) -> int:
        """Insert or update every catalog entry. Returns the number processed."""
        for definition in CATALOG:
            self._upsert(definition)
        logger.info("Seeded catalog (%d tools)", len(CATALOG))
        return len(CATALOG)

    def _upsert(self, d: ToolDef) -> ToolRegistry:
        tool = self.tools.get_by_slug(d.slug)
        if tool is None:
            tool = ToolRegistry(slug=d.slug)
            self.session.add(tool)
        # Update declarative fields (keeps DB in sync with catalog changes).
        tool.name = d.name
        tool.description = d.description
        tool.category = d.category
        tool.team = d.team
        tool.beginner_note = d.beginner_note
        tool.install_method = d.install_method
        tool.install_target = d.install_target
        tool.run_command = d.run_command
        tool.docs_url = d.docs_url
        tool.license = d.license
        tool.requires_isolation = d.requires_isolation
        self.session.flush()

        self.tools.ensure_status(tool)
        self.tools.ensure_health(tool)
        self._sync_attack(d)
        return tool

    def _sync_attack(self, d: ToolDef) -> None:
        if not d.attack:
            return
        existing = set(
            self.session.execute(
                select(MitreMapping.technique_id).where(MitreMapping.tool_slug == d.slug)
            ).scalars().all()
        )
        for technique_id, technique_name, tactic in d.attack:
            if technique_id in existing:
                continue
            self.session.add(
                MitreMapping(
                    tool_slug=d.slug,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                )
            )
        self.session.flush()

    # ----- queries ----------------------------------------------------------
    def list_for_team(self, team: str) -> list[ToolRegistry]:
        return self.tools.list_by_team(team)

    def list_categories(self, team: str | None = None) -> list[str]:
        return categories(team)

    def get(self, slug: str) -> ToolRegistry | None:
        return self.tools.get_by_slug(slug)

    def snapshot(self, team: str = "both") -> list[ToolRow]:
        """Return flat ToolRow snapshots (safe to use after the session closes)."""
        # A tool is "runnable" from the browser terminal only if the catalog
        # gives it a run command OR a detectable binary. Services / GUIs /
        # libraries (e.g. MISP, BloodHound, Impacket) have neither, so the UI
        # routes their Run button to Docs instead of a dead-end error.
        runnable_slugs = {
            d.slug for d in CATALOG if (d.run_command or d.check_binary)
        }
        rows: list[ToolRow] = []
        for tool in self.tools.list_by_team(team):
            status = self.tools.ensure_status(tool)
            health = self.tools.ensure_health(tool)
            rows.append(
                ToolRow(
                    slug=tool.slug,
                    name=tool.name,
                    description=tool.description,
                    category=tool.category,
                    team=tool.team,
                    beginner_note=tool.beginner_note,
                    install_method=tool.install_method,
                    docs_url=tool.docs_url,
                    license=tool.license,
                    requires_isolation=tool.requires_isolation,
                    installed=bool(status and status.installed),
                    health_status=health.status if health else "unknown",
                    health_score=health.score if health else 0,
                    runnable=tool.slug in runnable_slugs,
                )
            )
        return rows

    @staticmethod
    def catalog_size(team: str = "both") -> int:
        return len(catalog_by_team(team))
