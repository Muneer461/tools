"""MITRE ATT&CK knowledge base (curated subset) for beginners.

This is a small, self-contained slice of the ATT&CK Enterprise matrix - enough
to teach the concepts (tactics vs. techniques) and to map ZorkSec tools to the
techniques they help with, without requiring a network download of the full
STIX bundle. Each technique carries a plain-English beginner explanation.
"""

from __future__ import annotations

from dataclasses import dataclass

# The 14 ATT&CK Enterprise tactics, in kill-chain order, with beginner notes.
TACTICS: list[tuple[str, str, str]] = [
    ("TA0043", "Reconnaissance", "Gathering information about a target before attacking."),
    ("TA0042", "Resource Development", "Setting up the infrastructure/tools an attacker will use."),
    ("TA0001", "Initial Access", "Getting the first foothold inside a network."),
    ("TA0002", "Execution", "Running malicious code on a system."),
    ("TA0003", "Persistence", "Keeping access even after reboots or logoffs."),
    ("TA0004", "Privilege Escalation", "Gaining higher permissions (e.g. admin/root)."),
    ("TA0005", "Defense Evasion", "Avoiding detection by security tools."),
    ("TA0006", "Credential Access", "Stealing usernames and passwords."),
    ("TA0007", "Discovery", "Looking around to understand the environment."),
    ("TA0008", "Lateral Movement", "Moving from one system to another inside the network."),
    ("TA0009", "Collection", "Gathering the data the attacker wants."),
    ("TA0011", "Command and Control", "Communicating with compromised systems remotely."),
    ("TA0010", "Exfiltration", "Stealing data out of the network."),
    ("TA0040", "Impact", "Destroying, encrypting, or disrupting systems/data."),
]


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    explanation: str


# Curated techniques commonly seen by L1 SOC analysts.
TECHNIQUES: list[Technique] = [
    Technique("T1595", "Active Scanning", "Reconnaissance",
              "Probing a target's systems (e.g. port scanning) to find weaknesses."),
    Technique("T1190", "Exploit Public-Facing Application", "Initial Access",
              "Attacking an internet-facing app (e.g. a web server) to break in."),
    Technique("T1566", "Phishing", "Initial Access",
              "Tricking a user via email/message into giving access or running malware."),
    Technique("T1059", "Command and Scripting Interpreter", "Execution",
              "Running commands/scripts (PowerShell, bash) to execute attacker code."),
    Technique("T1053", "Scheduled Task/Job", "Persistence",
              "Using scheduled tasks/cron to keep malware running over time."),
    Technique("T1547", "Boot or Logon Autostart Execution", "Persistence",
              "Auto-starting malware when the system boots or a user logs in."),
    Technique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
              "Bypassing controls like sudo/UAC to gain higher privileges."),
    Technique("T1070", "Indicator Removal", "Defense Evasion",
              "Deleting logs or artifacts to hide the attacker's tracks."),
    Technique("T1003", "OS Credential Dumping", "Credential Access",
              "Stealing password hashes/credentials from the operating system."),
    Technique("T1110", "Brute Force", "Credential Access",
              "Guessing passwords by trying many combinations."),
    Technique("T1046", "Network Service Discovery", "Discovery",
              "Finding services/ports running on hosts across the network."),
    Technique("T1018", "Remote System Discovery", "Discovery",
              "Listing other machines on the network to plan movement."),
    Technique("T1021", "Remote Services", "Lateral Movement",
              "Using RDP/SSH/SMB to move to other systems."),
    Technique("T1071", "Application Layer Protocol", "Command and Control",
              "Hiding C2 traffic inside normal protocols like HTTP/DNS."),
    Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              "Sending stolen data out through the same channel used for control."),
    Technique("T1486", "Data Encrypted for Impact", "Impact",
              "Ransomware encrypting files to extort the victim."),
]

_TACTIC_BY_NAME = {name: (tid, note) for tid, name, note in TACTICS}
_TECHNIQUE_BY_ID = {t.technique_id: t for t in TECHNIQUES}


def tactic_order(tactic_name: str) -> int:
    """Return the kill-chain index of a tactic (for sorting)."""
    for idx, (_tid, name, _note) in enumerate(TACTICS):
        if name == tactic_name:
            return idx
    return len(TACTICS)


def get_technique(technique_id: str) -> Technique | None:
    return _TECHNIQUE_BY_ID.get(technique_id)


def technique_explanation(technique_id: str) -> str:
    tech = _TECHNIQUE_BY_ID.get(technique_id)
    return tech.explanation if tech else "No description available for this technique."
