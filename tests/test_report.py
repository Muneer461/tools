"""Tests for the reporting engine."""

from __future__ import annotations

import json

import pytest

from zorksec.db.session import init_db, session_scope
from zorksec.services.report_service import (
    ReportService,
    build_template,
    render,
    render_csv,
    render_json,
    render_markdown,
)


def test_build_template_known_types():
    for rtype in ReportService.report_types():
        doc = build_template(rtype, f"Test {rtype}", {"summary": "hi"})
        assert doc.report_type == rtype
        assert doc.sections


def test_build_template_unknown_type_raises():
    with pytest.raises(ValueError):
        build_template("nonsense", "x")


def test_markdown_render_contains_sections():
    doc = build_template("incident", "Phishing Incident",
                         {"summary": "User clicked a link.",
                          "iocs": ["evil.test", "1.2.3.4"]})
    md = render_markdown(doc)
    assert "# Phishing Incident" in md
    assert "## Indicators of Compromise" in md
    assert "- evil.test" in md


def test_json_render_roundtrip():
    doc = build_template("dfir", "Case 1", {"evidence": ["disk.img"]})
    data = json.loads(render_json(doc))
    assert data["title"] == "Case 1"
    assert data["report_type"] == "dfir"
    assert any(s["heading"] == "Evidence Acquired" for s in data["sections"])


def test_csv_render_has_rows():
    doc = build_template("assessment", "Scan", {"findings": ["open port 22"]})
    csv_text = render_csv(doc)
    assert "section,type,content" in csv_text
    assert "open port 22" in csv_text


def test_render_dispatch_extensions():
    doc = build_template("executive", "Exec Brief", {"impact": "low"})
    for fmt, ext in [("markdown", "md"), ("html", "html"),
                     ("json", "json"), ("csv", "csv")]:
        content, extension = render(doc, fmt)
        assert isinstance(content, bytes) and content
        assert extension == ext


def test_render_unsupported_format_raises():
    doc = build_template("executive", "x")
    with pytest.raises(ValueError):
        render(doc, "xml")


def test_generate_persists_report(zorksec_home):
    init_db()
    with session_scope() as s:
        svc = ReportService(s)
        report = svc.generate("incident", "Saved Incident", {"summary": "test"})
        assert report.id is not None
    with session_scope() as s:
        svc = ReportService(s)
        recent = svc.reports.recent()
        assert any(r.title == "Saved Incident" for r in recent)


def test_export_to_file_writes(zorksec_home):
    init_db()
    with session_scope() as s:
        svc = ReportService(s)
        path = svc.export_to_file("threat_hunt", "Hunt Report",
                                  {"hypothesis": "lateral movement"}, "html")
        assert path.endswith(".html")
        from pathlib import Path
        assert Path(path).exists()
        assert "Hunt Report" in Path(path).read_text(encoding="utf-8")


def test_available_formats_always_has_text():
    formats = ReportService.formats()
    for base in ("markdown", "html", "json", "csv"):
        assert base in formats
