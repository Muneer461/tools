"""Tests for the dependency engine.

These assert on structure/behaviour rather than the host's exact toolchain, so
they pass in any environment. Python and Git should always be detected here.
"""

from __future__ import annotations

from zorksec.services.dependency_service import DependencyService


def test_detect_returns_all_known_dependencies():
    deps = DependencyService().detect()
    keys = {d.key for d in deps}
    assert {"python", "git", "docker", "compose", "go", "cargo", "java"} == keys


def test_python_detected_with_version():
    deps = {d.key: d for d in DependencyService().detect()}
    assert deps["python"].present is True
    assert deps["python"].version is not None


def test_missing_returns_subset():
    svc = DependencyService()
    missing = svc.missing()
    assert all(d.present is False for d in missing)
