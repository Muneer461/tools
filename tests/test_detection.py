"""Tests for the Detection Engineering workspace service."""

from __future__ import annotations

from zorksec.services.detection_service import (
    DetectionService,
    evaluate,
    parse_rule,
)


def test_templates_parse_and_validate():
    for name, text in DetectionService.templates().items():
        rule = parse_rule(text)
        assert rule.valid, f"template {name} should be valid: {rule.issues}"


def test_attack_tag_extraction():
    rule = parse_rule(DetectionService.templates()["suspicious_process"])
    assert "T1059" in rule.attack_techniques()


def test_invalid_rule_missing_condition():
    text = """title: Broken
logsource:
  product: windows
detection:
  selection:
    EventID: 4625
level: medium
"""
    rule = parse_rule(text)
    assert rule.valid is False
    assert any(i.field == "detection.condition" for i in rule.issues)


def test_invalid_level_flagged():
    text = """title: Bad Level
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
level: spicy
"""
    rule = parse_rule(text)
    assert rule.valid is False
    assert any(i.field == "level" for i in rule.issues)


def test_rule_fires_on_matching_event():
    rule = parse_rule(DetectionService.templates()["failed_logins"])
    assert evaluate(rule, {"EventID": 4625}) is True
    assert evaluate(rule, {"EventID": 4624}) is False


def test_contains_and_endswith_modifiers():
    text = """title: Encoded PS
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
tags:
  - attack.t1059
"""
    rule = parse_rule(text)
    assert rule.valid
    good = {"Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell -enc ZQBjAGgAbwA="}
    bad = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "dir"}
    assert evaluate(rule, good) is True
    assert evaluate(rule, bad) is False


def test_test_rule_helper_reports_everything():
    text = DetectionService.templates()["failed_logins"]
    result = DetectionService.test_rule(text, {"EventID": 4625})
    assert result["valid"] is True
    assert result["fired"] is True
    assert "T1110" in result["attack"]
