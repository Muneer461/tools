"""ATT&CK mapping engine.

Combines the curated ATT&CK knowledge base (:mod:`zorksec.detection.attack`)
with the per-tool mappings stored in the ``mitre_mappings`` table (seeded from
the catalog). Provides:
  * the tactic/technique reference (for teaching)
  * tool -> techniques lookups
  * a coverage view: which tactics your installed tools touch
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import MitreMapping
from zorksec.detection.attack import (
    TACTICS,
    TECHNIQUES,
    Technique,
    tactic_order,
    technique_explanation,
)
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str
    tactic: str
    explanation: str
    tools: list[str]  # tool slugs that map to this technique


@dataclass
class TacticCoverage:
    tactic_id: str
    tactic: str
    explanation: str
    technique_count: int
    covered_count: int  # techniques with at least one mapped tool


class AttackService:
    def __init__(self, session: Session) -> None:
        self.session = session

    # ----- reference --------------------------------------------------------
    @staticmethod
    def tactics() -> list[tuple[str, str, str]]:
        return list(TACTICS)

    @staticmethod
    def techniques() -> list[Technique]:
        return list(TECHNIQUES)

    @staticmethod
    def explain(technique_id: str) -> str:
        return technique_explanation(technique_id)

    # ----- mappings ---------------------------------------------------------
    def techniques_for_tool(self, slug: str) -> list[MitreMapping]:
        stmt = select(MitreMapping).where(MitreMapping.tool_slug == slug)
        return list(self.session.execute(stmt).scalars().all())

    def tools_for_technique(self, technique_id: str) -> list[str]:
        stmt = select(MitreMapping.tool_slug).where(
            MitreMapping.technique_id == technique_id
        )
        return list(self.session.execute(stmt).scalars().all())

    def coverage_by_technique(self) -> list[TechniqueCoverage]:
        """One row per known technique, with the tools that map to it."""
        rows: list[TechniqueCoverage] = []
        for tech in TECHNIQUES:
            tools = self.tools_for_technique(tech.technique_id)
            rows.append(
                TechniqueCoverage(
                    technique_id=tech.technique_id,
                    name=tech.name,
                    tactic=tech.tactic,
                    explanation=tech.explanation,
                    tools=tools,
                )
            )
        rows.sort(key=lambda r: (tactic_order(r.tactic), r.technique_id))
        return rows

    def coverage_by_tactic(self) -> list[TacticCoverage]:
        """Roll technique coverage up to the tactic level (for the dashboard)."""
        by_tech = self.coverage_by_technique()
        summary: dict[str, TacticCoverage] = {}
        for tid, name, note in TACTICS:
            summary[name] = TacticCoverage(tid, name, note, 0, 0)
        for cov in by_tech:
            tac = summary.get(cov.tactic)
            if tac is None:
                continue
            tac.technique_count += 1
            if cov.tools:
                tac.covered_count += 1
        ordered = sorted(summary.values(), key=lambda t: tactic_order(t.tactic))
        return ordered

    def mapped_technique_ids(self) -> set[str]:
        stmt = select(MitreMapping.technique_id).distinct()
        return set(self.session.execute(stmt).scalars().all())
