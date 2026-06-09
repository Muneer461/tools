"""Tests for the Kali Linux Diagnostics service."""

from __future__ import annotations

from zorksec.services.kali_diagnostics_service import (
    STATUS_OK,
    STATUS_SKIPPED,
    KaliCheck,
    KaliDiagnosticsService,
    KaliReport,
)


def test_scan_returns_report_with_all_checks():
    report = KaliDiagnosticsService().scan()
    keys = {c.key for c in report.checks}
    expected = {"dpkg_interrupted", "broken_deps", "half_installed", "apt_lock",
                "apt_indexes", "kali_repo", "path_exports"}
    assert expected.issubset(keys)
    assert report.overall in {"ok", "warning", "fail", "skipped"}


def test_report_overall_is_worst_status():
    report = KaliReport(distro="kali", is_kali=True, checks=[
        KaliCheck("a", "A", STATUS_OK),
        KaliCheck("b", "B", "warning"),
        KaliCheck("c", "C", "fail"),
    ])
    assert report.overall == "fail"
    assert len(report.failing()) == 2


def test_check_to_dict_exposes_fixable_flag():
    fixable = KaliCheck("k", "K", "fail", repair_command="sudo -n true")
    not_fixable = KaliCheck("k2", "K2", "fail", repair_command=None)
    assert fixable.to_dict()["fixable"] is True
    assert not_fixable.to_dict()["fixable"] is False


def test_manual_guide_returns_steps_for_failing(monkeypatch):
    svc = KaliDiagnosticsService()
    report = KaliReport(distro="kali", is_kali=True, checks=[
        KaliCheck("broken_deps", "Broken", "fail",
                  manual_steps=["sudo apt-get -f install"]),
    ])
    monkeypatch.setattr(svc, "scan", lambda: report)
    guide = svc.manual_guide()
    assert guide["broken_deps"] == ["sudo apt-get -f install"]


def test_root_cause_analysis_lists_failures(monkeypatch):
    svc = KaliDiagnosticsService()
    report = KaliReport(distro="kali", is_kali=True, checks=[
        KaliCheck("apt_lock", "Lock", "warning", root_cause="stale lock"),
    ])
    monkeypatch.setattr(svc, "scan", lambda: report)
    causes = svc.root_cause_analysis()
    assert any("Lock" in c for c in causes)


def test_auto_repair_handles_no_failures(monkeypatch):
    svc = KaliDiagnosticsService()
    report = KaliReport(distro="kali", is_kali=True,
                        checks=[KaliCheck("a", "A", STATUS_OK)])
    monkeypatch.setattr(svc, "scan", lambda: report)
    results = svc.auto_repair()
    assert results[0].key == "none"
    assert results[0].success is True


def test_auto_repair_skips_unfixable(monkeypatch):
    svc = KaliDiagnosticsService()
    report = KaliReport(distro="kali", is_kali=True, checks=[
        KaliCheck("kali_repo", "Repo", "warning", repair_command=None,
                  manual_steps=["edit sources.list"]),
    ])
    monkeypatch.setattr(svc, "scan", lambda: report)
    results = svc.auto_repair()
    assert results[0].attempted is False
    assert results[0].mode == "manual"
