"""Registry service: seed the catalog into the DB and query it.

Seeding is idempotent - it upserts each :class:`ToolDef` by slug, so it can be
re-run after catalog updates without creating duplicates.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import MitreMapping, ToolRegistry
from zorksec.registry.catalog import CATALOG, ToolDef, catalog_by_team, categories
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)


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

    @staticmethod
    def catalog_size(team: str = "both") -> int:
        return len(catalog_by_team(team))
