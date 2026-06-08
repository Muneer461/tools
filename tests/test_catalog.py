"""Tests for catalog integrity and registry seeding."""

from __future__ import annotations

from zorksec.config import get_settings
from zorksec.db.session import init_db, session_scope
from zorksec.registry.catalog import CATALOG, catalog_by_team
from zorksec.services.registry_service import RegistryService


def test_catalog_slugs_unique():
    slugs = [t.slug for t in CATALOG]
    assert len(slugs) == len(set(slugs)), "duplicate slugs in catalog"


def test_catalog_fields_valid():
    valid_teams = {"blue", "red", "both"}
    valid_methods = {"apt", "pip", "go", "snap", "github", "docker", "builtin"}
    for t in CATALOG:
        assert t.team in valid_teams, f"{t.slug}: bad team {t.team}"
        assert t.install_method in valid_methods, f"{t.slug}: bad method {t.install_method}"
        assert t.beginner_note, f"{t.slug}: missing beginner note"


def test_catalog_by_team_filtering():
    blue = catalog_by_team("blue")
    red = catalog_by_team("red")
    assert all(t.team in ("blue", "both") for t in blue)
    assert all(t.team in ("red", "both") for t in red)
    # 'both' tools appear in both profiles
    both_slugs = {t.slug for t in CATALOG if t.team == "both"}
    assert both_slugs.issubset({t.slug for t in blue})
    assert both_slugs.issubset({t.slug for t in red})


def test_seed_is_idempotent(zorksec_home):
    init_db()
    with session_scope() as session:
        svc = RegistryService(session)
        first = svc.seed_catalog()
    with session_scope() as session:
        svc = RegistryService(session)
        svc.seed_catalog()
        assert svc.tools.count() == first  # no duplicates on re-seed


def test_seed_creates_status_and_attack(zorksec_home):
    init_db()
    with session_scope() as session:
        RegistryService(session).seed_catalog()
    with session_scope() as session:
        svc = RegistryService(session)
        nmap = svc.get("nmap")
        assert nmap is not None
        assert nmap.status is not None
        # nmap has an ATT&CK mapping in the catalog
        from zorksec.db.models import MitreMapping
        from sqlalchemy import select
        techniques = session.execute(
            select(MitreMapping).where(MitreMapping.tool_slug == "nmap")
        ).scalars().all()
        assert any(m.technique_id == "T1046" for m in techniques)
