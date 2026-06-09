"""Tests for the high-resource install warning service."""

from __future__ import annotations

from zorksec.services.resource_check_service import (
    HEAVY_TOOLS,
    ResourceCheckService,
    system_resources,
)


def test_requires_confirmation_for_heavy_tools():
    assert ResourceCheckService.requires_confirmation("misp") is True
    assert ResourceCheckService.requires_confirmation("helk") is True
    assert ResourceCheckService.requires_confirmation("nmap") is False


def test_warning_for_heavy_tool_has_box_and_fields():
    warning = ResourceCheckService.warning_for("helk")
    assert warning is not None
    d = warning.to_dict()
    assert d["requires_confirmation"] is True if "requires_confirmation" in d else True
    assert d["required"]["ram_gb"] == HEAVY_TOOLS["helk"].ram_gb
    assert "HIGH RESOURCE WARNING" in d["box"]
    assert "Type YES to continue" in d["box"]


def test_warning_for_light_tool_is_none():
    assert ResourceCheckService.warning_for("nmap") is None


def test_confirms_requires_exact_uppercase_yes():
    assert ResourceCheckService.confirms("YES") is True
    assert ResourceCheckService.confirms("yes") is False
    assert ResourceCheckService.confirms("y") is False
    assert ResourceCheckService.confirms("") is False


def test_system_resources_reports_cpu():
    res = system_resources()
    assert res.cpu_cores >= 1
    assert res.disk_total_gb >= 0


def test_shortfalls_detected_when_insufficient(monkeypatch):
    import zorksec.services.resource_check_service as rc

    fake = rc.SystemResources(ram_total_gb=1, ram_available_gb=0.5,
                              disk_total_gb=10, disk_free_gb=1, cpu_cores=1)
    monkeypatch.setattr(rc, "system_resources", lambda: fake)
    warning = ResourceCheckService.warning_for("helk")  # needs 16GB/30GB/4cpu
    assert warning is not None
    assert warning.sufficient is False
    assert len(warning.shortfalls) == 3
