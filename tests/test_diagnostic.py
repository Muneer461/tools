"""Tests for the Diagnostic Center service."""

from __future__ import annotations

from zorksec.services.diagnostic_service import (
    STATUS_FAIL,
    STATUS_OK,
    STATUS_WARNING,
    DiagnosticReport,
    DiagnosticService,
    CheckResult,
)


def test_full_diagnostic_runs_all_checks(zorksec_home):
    report = DiagnosticService().run_full_diagnostic()
    keys = {c.key for c in report.checks}
    expected = {"broken_packages", "dpkg", "path", "missing_binaries", "python",
                "go", "cargo", "disk", "memory", "network", "permissions"}
    assert expected.issubset(keys)
    # Overall status is one of the known vocabulary values.
    assert report.overall in {STATUS_OK, STATUS_WARNING, STATUS_FAIL, "unknown"}


def test_python_check_passes_on_supported_interpreter(zorksec_home):
    # The test runner uses Python >= 3.10, so this check must be OK.
    result = DiagnosticService().check_python()
    assert result.status == STATUS_OK
    assert "Python" in result.detail


def test_report_counts_and_overall():
    report = DiagnosticReport(checks=[
        CheckResult("a", "A", STATUS_OK),
        CheckResult("b", "B", STATUS_WARNING),
        CheckResult("c", "C", STATUS_FAIL),
    ])
    counts = report.counts
    assert counts[STATUS_OK] == 1 and counts[STATUS_FAIL] == 1
    assert report.overall == STATUS_FAIL  # worst status wins
    assert len(report.failing()) == 2


def test_manual_repair_guide_has_entries(zorksec_home):
    guide = DiagnosticService().manual_repair_guide()
    assert "python" in guide and "disk" in guide
    assert all(isinstance(v, str) and v for v in guide.values())


def test_root_cause_analysis_returns_lines(zorksec_home):
    report = DiagnosticReport(checks=[
        CheckResult("disk", "Disk", STATUS_FAIL, "full",
                    root_cause="root filesystem is full"),
    ])
    causes = DiagnosticService().root_cause_analysis(report)
    assert any("Disk" in c for c in causes)


def test_auto_repair_handles_no_failures():
    report = DiagnosticReport(checks=[CheckResult("a", "A", STATUS_OK)])
    svc = DiagnosticService()
    # Inject a passing report so auto_repair has nothing to do.
    svc.run_full_diagnostic = lambda: report  # type: ignore[method-assign]
    results = svc.auto_repair()
    assert results[0].key == "none"
    assert results[0].success is True


def test_export_report_writes_file(zorksec_home):
    svc = DiagnosticService()
    path = svc.export_report(fmt="markdown")
    assert path.endswith(".md")
    from pathlib import Path
    assert Path(path).exists()
