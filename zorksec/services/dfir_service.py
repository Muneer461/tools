"""DFIR (Digital Forensics & Incident Response) workspace service.

Beginner-focused: provides guided playbooks and artifact checklists rather than
running invasive forensic actions automatically. Each playbook lists ordered
steps, the relevant ZorkSec tool slugs, and what an L1 analyst should record.

A lightweight triage helper computes a simple severity from observed signals so
newcomers learn to prioritise.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlaybookStep:
    title: str
    detail: str
    tools: list[str] = field(default_factory=list)


@dataclass
class Playbook:
    key: str
    name: str
    summary: str
    steps: list[PlaybookStep]


PLAYBOOKS: list[Playbook] = [
    Playbook(
        "memory", "Memory Acquisition & Analysis",
        "Capture and examine RAM to find hidden processes, injected code, and network activity.",
        [
            PlaybookStep("Preserve volatile data first",
                         "RAM is lost on shutdown. Capture memory before powering off.",
                         ["volatility3"]),
            PlaybookStep("Identify the OS profile",
                         "Confirm the image's OS/version so analysis plugins work correctly.",
                         ["volatility3"]),
            PlaybookStep("List processes and network connections",
                         "Look for unusual parent/child process trees and odd connections.",
                         ["volatility3"]),
            PlaybookStep("Record findings",
                         "Note suspicious PIDs, hashes, and IOCs for the case file.", []),
        ],
    ),
    Playbook(
        "disk", "Disk Image Triage",
        "Work from a forensic copy of a disk to find evidence without altering the original.",
        [
            PlaybookStep("Work on a copy, never the original",
                         "Image the disk and verify the hash to preserve integrity.", []),
            PlaybookStep("Build a timeline",
                         "Generate a super-timeline of file/registry events.", ["plaso"]),
            PlaybookStep("Browse artifacts visually",
                         "Use a GUI to review files, browser history, and deleted items.",
                         ["autopsy"]),
            PlaybookStep("Extract embedded data",
                         "Carve files and inspect binaries/firmware where relevant.",
                         ["binwalk"]),
        ],
    ),
    Playbook(
        "logs", "Windows Event Log Triage",
        "Quickly turn noisy event logs into a prioritised list of suspicious activity.",
        [
            PlaybookStep("Collect the EVTX files",
                         "Gather Security/System/PowerShell logs from the host.", []),
            PlaybookStep("Run fast detections",
                         "Apply Sigma-based rules to surface known-bad patterns.",
                         ["hayabusa", "chainsaw", "zircolite"]),
            PlaybookStep("Pivot on findings",
                         "Investigate logons, new accounts, and service installs.", []),
            PlaybookStep("Map to ATT&CK",
                         "Tag each finding with a technique to show what happened.", []),
        ],
    ),
    Playbook(
        "live", "Live Endpoint Response",
        "Investigate a running machine (or fleet) during an active incident.",
        [
            PlaybookStep("Question the endpoint",
                         "Use osquery to ask the system about processes, users, and files.",
                         ["osquery"]),
            PlaybookStep("Hunt at scale",
                         "Run VQL hunts across endpoints to find the same indicators.",
                         ["velociraptor"]),
            PlaybookStep("Contain if authorised",
                         "Isolate the host per your IR policy before eradication.", []),
        ],
    ),
]

_PLAYBOOK_BY_KEY = {p.key: p for p in PLAYBOOKS}


@dataclass
class TriageResult:
    severity: str       # low | medium | high | critical
    score: int          # 0-100
    rationale: list[str]


# Signal -> weight. Beginners learn which signals raise severity.
_SIGNAL_WEIGHTS: dict[str, int] = {
    "known_malware": 50,
    "c2_traffic": 40,
    "credential_dumping": 40,
    "ransomware_note": 60,
    "new_admin_account": 30,
    "failed_then_success_login": 20,
    "scheduled_task_created": 15,
    "scanning_activity": 10,
    "single_failed_login": 2,
}


def triage(signals: list[str]) -> TriageResult:
    """Compute a simple severity from observed signals (teaching aid)."""
    score = 0
    rationale: list[str] = []
    for sig in signals:
        weight = _SIGNAL_WEIGHTS.get(sig)
        if weight is None:
            rationale.append(f"unknown signal '{sig}' (ignored)")
            continue
        score += weight
        rationale.append(f"{sig} (+{weight})")
    score = min(100, score)
    if score >= 80:
        severity = "critical"
    elif score >= 50:
        severity = "high"
    elif score >= 20:
        severity = "medium"
    else:
        severity = "low"
    if not rationale:
        rationale.append("no recognised signals")
    return TriageResult(severity=severity, score=score, rationale=rationale)


class DfirService:
    """Serves DFIR playbooks and triage scoring (no destructive actions)."""

    @staticmethod
    def playbooks() -> list[Playbook]:
        return list(PLAYBOOKS)

    @staticmethod
    def get_playbook(key: str) -> Playbook | None:
        return _PLAYBOOK_BY_KEY.get(key)

    @staticmethod
    def triage(signals: list[str]) -> TriageResult:
        return triage(signals)
