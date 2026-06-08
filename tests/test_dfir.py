"""Tests for the DFIR workspace service."""

from __future__ import annotations

from zorksec.services.dfir_service import DfirService, triage


def test_playbooks_exist_and_have_steps():
    pbs = DfirService.playbooks()
    assert len(pbs) >= 4
    for pb in pbs:
        assert pb.steps, f"playbook {pb.key} has no steps"
        assert pb.summary


def test_get_playbook_by_key():
    pb = DfirService.get_playbook("memory")
    assert pb is not None
    assert "volatility3" in pb.steps[0].tools
    assert DfirService.get_playbook("nope") is None


def test_triage_low():
    result = triage(["single_failed_login"])
    assert result.severity == "low"
    assert result.score < 20


def test_triage_critical():
    result = triage(["ransomware_note", "known_malware"])
    assert result.severity == "critical"
    assert result.score == 100  # capped


def test_triage_medium_high_boundary():
    assert triage(["new_admin_account"]).severity == "medium"  # 30
    assert triage(["credential_dumping", "new_admin_account"]).severity == "high"  # 70


def test_triage_unknown_signal_ignored():
    result = triage(["totally_made_up"])
    assert result.severity == "low"
    assert any("unknown signal" in r for r in result.rationale)
