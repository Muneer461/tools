"""Detection Engineering workspace service.

Teaches the Sigma rule lifecycle without requiring the full pySigma toolchain:
  * a minimal Sigma rule parser/validator (YAML if available, else a tolerant
    line parser) that checks the required structure beginners must learn
  * starter rule templates
  * ATT&CK linkage (a rule's ``tags`` like ``attack.t1059`` are surfaced)
  * a tiny matcher that evaluates a parsed rule's simple field equality
    conditions against a sample log event (for "does my rule fire?" practice)

This is a learning aid, not a production SIEM backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

try:  # PyYAML ships with many environments; fall back gracefully if absent.
    import yaml  # type: ignore

    _YAML = True
except ImportError:  # pragma: no cover
    _YAML = False


@dataclass
class ValidationIssue:
    field: str
    message: str


@dataclass
class ParsedRule:
    title: str
    logsource: dict
    detection: dict
    level: str
    tags: list[str] = field(default_factory=list)
    valid: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)

    def attack_techniques(self) -> list[str]:
        """Extract ATT&CK technique IDs from Sigma-style tags (attack.tNNNN)."""
        out: list[str] = []
        for tag in self.tags:
            m = re.match(r"attack\.t(\d{4,5})(\.\d+)?$", tag.strip().lower())
            if m:
                out.append("T" + m.group(1) + (m.group(2) or ""))
        return out


REQUIRED_LEVELS = {"informational", "low", "medium", "high", "critical"}

RULE_TEMPLATES: dict[str, str] = {
    "suspicious_process": """title: Suspicious PowerShell Encoded Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
tags:
  - attack.t1059
  - attack.execution
""",
    "failed_logins": """title: Multiple Failed Logons
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
tags:
  - attack.t1110
""",
}


def _parse_yaml(text: str) -> dict | None:
    if not _YAML:
        return None
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _parse_fallback(text: str) -> dict:
    """Very small indentation-aware parser for the subset we need (no PyYAML)."""
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1] if stack else root
        if line.startswith("- "):
            parent.setdefault("__list__", []).append(line[2:].strip())
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                parent[key] = _coerce(val)
            else:
                child: dict = {}
                parent[key] = child
                stack.append((indent, child))
    return _normalise_lists(root)


def _coerce(val: str):
    val = val.strip().strip("'\"")
    if val.isdigit():
        return int(val)
    return val


def _normalise_lists(node):
    """Convert our temporary __list__ markers into real lists."""
    if isinstance(node, dict):
        if set(node.keys()) == {"__list__"}:
            return node["__list__"]
        return {k: _normalise_lists(v) for k, v in node.items()}
    return node


def parse_rule(text: str) -> ParsedRule:
    data = _parse_yaml(text)
    if data is None:
        data = _parse_fallback(text)

    issues: list[ValidationIssue] = []
    title = data.get("title", "") if isinstance(data, dict) else ""
    logsource = data.get("logsource", {}) if isinstance(data, dict) else {}
    detection = data.get("detection", {}) if isinstance(data, dict) else {}
    level = (data.get("level", "") or "").lower() if isinstance(data, dict) else ""
    tags = data.get("tags", []) if isinstance(data, dict) else []
    if isinstance(tags, str):
        tags = [tags]

    if not title:
        issues.append(ValidationIssue("title", "A rule must have a title."))
    if not logsource:
        issues.append(ValidationIssue("logsource", "Define a logsource (what data this applies to)."))
    if not detection:
        issues.append(ValidationIssue("detection", "Define a detection block with conditions."))
    elif "condition" not in detection:
        issues.append(ValidationIssue("detection.condition",
                                      "The detection block needs a 'condition'."))
    if level and level not in REQUIRED_LEVELS:
        issues.append(ValidationIssue("level",
                                      f"Level '{level}' is not one of {sorted(REQUIRED_LEVELS)}."))

    return ParsedRule(
        title=title or "(untitled)",
        logsource=logsource if isinstance(logsource, dict) else {},
        detection=detection if isinstance(detection, dict) else {},
        level=level or "unspecified",
        tags=tags if isinstance(tags, list) else [],
        valid=len(issues) == 0,
        issues=issues,
    )


def evaluate(rule: ParsedRule, event: dict) -> bool:
    """Evaluate a rule's 'selection' equality conditions against an event.

    Supports the common Sigma modifiers ``contains`` and ``endswith`` and plain
    equality. Only the 'selection' map referenced by 'condition: selection' is
    evaluated - enough for beginners to see a rule fire.
    """
    detection = rule.detection
    condition = str(detection.get("condition", "")).strip()
    if condition != "selection":
        return False
    selection = detection.get("selection", {})
    if not isinstance(selection, dict):
        return False
    for key, expected in selection.items():
        field_name, _, modifier = key.partition("|")
        actual = event.get(field_name)
        if actual is None:
            return False
        actual_s = str(actual)
        expected_s = str(expected)
        if modifier == "contains":
            if expected_s not in actual_s:
                return False
        elif modifier == "endswith":
            if not actual_s.endswith(expected_s.replace("\\\\", "\\")):
                return False
        else:
            if actual_s != expected_s:
                return False
    return True


class DetectionService:
    @staticmethod
    def templates() -> dict[str, str]:
        return dict(RULE_TEMPLATES)

    @staticmethod
    def parse(text: str) -> ParsedRule:
        return parse_rule(text)

    @staticmethod
    def validate(text: str) -> ParsedRule:
        return parse_rule(text)

    @staticmethod
    def test_rule(text: str, event: dict) -> dict:
        rule = parse_rule(text)
        fired = evaluate(rule, event) if rule.valid else False
        return {
            "valid": rule.valid,
            "title": rule.title,
            "level": rule.level,
            "attack": rule.attack_techniques(),
            "issues": [{"field": i.field, "message": i.message} for i in rule.issues],
            "fired": fired,
        }
