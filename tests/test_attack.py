"""Tests for the ATT&CK mapping engine."""

from __future__ import annotations

from zorksec.db.session import init_db, session_scope
from zorksec.detection.attack import TACTICS, TECHNIQUES
from zorksec.services.attack_service import AttackService
from zorksec.services.registry_service import RegistryService


def test_knowledge_base_integrity():
    assert len(TACTICS) == 14
    tactic_names = {name for _id, name, _note in TACTICS}
    for tech in TECHNIQUES:
        assert tech.tactic in tactic_names, f"{tech.technique_id} has unknown tactic"
    # ids unique
    ids = [t.technique_id for t in TECHNIQUES]
    assert len(ids) == len(set(ids))


def test_explain_known_and_unknown():
    assert "scanning" in AttackService.explain("T1595").lower()
    assert "No description" in AttackService.explain("T9999")


def test_tool_technique_mapping(zorksec_home):
    init_db()
    with session_scope() as s:
        RegistryService(s).seed_catalog()
    with session_scope() as s:
        svc = AttackService(s)
        # nmap maps to T1046 (Network Service Discovery) in the catalog
        nmap_techniques = {m.technique_id for m in svc.techniques_for_tool("nmap")}
        assert "T1046" in nmap_techniques
        assert "nmap" in svc.tools_for_technique("T1046")


def test_coverage_views(zorksec_home):
    init_db()
    with session_scope() as s:
        RegistryService(s).seed_catalog()
    with session_scope() as s:
        svc = AttackService(s)
        by_tech = svc.coverage_by_technique()
        assert len(by_tech) == len(TECHNIQUES)
        by_tactic = svc.coverage_by_tactic()
        assert len(by_tactic) == 14
        # At least one tactic should be covered by a seeded tool.
        assert any(t.covered_count > 0 for t in by_tactic)
