"""SOC utilities: IOC parsing/generation, log parsing, and PCAP analysis.

These are small, dependency-light helpers that round out the SOC analyst
workflow alongside the catalog tools (CyberChef, ATT&CK Navigator, tshark):

  * :func:`parse_iocs`     - extract & refang IOCs (IP/domain/URL/hash/email)
  * :func:`generate_iocs`  - render a typed indicator list to CSV / JSON / text
  * :func:`parse_logs`     - parse common log shapes (syslog, CLF, key=value, JSON)
  * :func:`analyze_pcap`   - summarise a capture file via tshark (best-effort)

Everything is offline and pure where possible so it is easy to unit-test and
never requires network access or API keys.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field

from zorksec.services.ti_service import classify_indicator, hash_kind

# ---------------------------------------------------------------------------
# IOC parsing
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\]]+", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


def refang(text: str) -> str:
    """Convert defanged indicators back to normal form for parsing.

    Handles the common conventions analysts use to share IOCs safely
    (``hxxp``, ``[.]``, ``(.)``, ``[:]``, ``[at]``).
    """
    if not text:
        return ""
    replacements = {
        "hxxps": "https", "hxxp": "http",
        "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".", " dot ": ".",
        "[:]": ":", "[://]": "://",
        "[at]": "@", "(at)": "@", " at ": "@",
    }
    out = text
    for needle, repl in replacements.items():
        out = out.replace(needle, repl)
    return out


@dataclass
class IocSet:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.urls) \
            + len(self.hashes) + len(self.emails)

    def to_dict(self) -> dict:
        return {
            "ips": self.ips, "domains": self.domains, "urls": self.urls,
            "hashes": self.hashes, "emails": self.emails, "total": self.total,
        }


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_iocs(text: str) -> IocSet:
    """Extract indicators of compromise from arbitrary text.

    URLs and emails are matched first and the hostnames/domains they contain are
    excluded from the standalone domain list to avoid double-counting.
    """
    refanged = refang(text or "")

    urls = _dedupe(_URL_RE.findall(refanged))
    emails = _dedupe(_EMAIL_RE.findall(refanged))
    ips = _dedupe(_IP_RE.findall(refanged))
    hashes = _dedupe(h.lower() for h in _HASH_RE.findall(refanged)
                     if hash_kind(h) is not None)

    # Domains: exclude those already represented inside URLs/emails/IPs.
    consumed = " ".join(urls + emails)
    raw_domains = _DOMAIN_RE.findall(refanged)
    domains: list[str] = []
    for dom in raw_domains:
        if _IP_RE.fullmatch(dom):
            continue
        if dom in consumed:
            continue
        # Skip things that look like a filename (e.g. report.txt) by checking
        # the IOC classifier agrees it is a domain.
        if classify_indicator(dom) == "domain":
            domains.append(dom)
    domains = _dedupe(domains)

    return IocSet(ips=ips, domains=domains, urls=urls, hashes=hashes, emails=emails)


# ---------------------------------------------------------------------------
# IOC generation
# ---------------------------------------------------------------------------
def generate_iocs(indicators: list[str], fmt: str = "csv",
                  context: str = "") -> str:
    """Render a list of indicators to a shareable format.

    Supported formats: ``csv`` (indicator,type,context), ``json`` (a minimal
    STIX-like bundle), and ``text`` (a defanged, human-readable list).
    """
    fmt = (fmt or "csv").lower()
    typed = [(value, classify_indicator(value)) for value in indicators if value.strip()]

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["indicator", "type", "context"])
        for value, ioc_type in typed:
            writer.writerow([value, ioc_type, context])
        return buf.getvalue()

    if fmt == "json":
        bundle = {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [
                {"type": "indicator", "pattern_type": "stix",
                 "value": value, "ioc_type": ioc_type, "context": context}
                for value, ioc_type in typed
            ],
        }
        return json.dumps(bundle, indent=2)

    if fmt == "text":
        # Defang for safe sharing in tickets/emails.
        lines = []
        for value, ioc_type in typed:
            safe = value.replace("http", "hxxp").replace(".", "[.]")
            lines.append(f"{ioc_type}: {safe}")
        return "\n".join(lines)

    raise ValueError(f"Unsupported format '{fmt}'. Use csv, json, or text.")


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")


def parse_log_line(line: str) -> dict:
    """Parse a single log line, returning a structured dict with a ``format``."""
    raw = line.strip()
    if not raw:
        return {"format": "empty", "raw": line}

    # JSON line.
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {"format": "json", "fields": data}
        except ValueError:
            pass

    m = _CLF_RE.match(raw)
    if m:
        d = m.groupdict()
        return {"format": "clf", "fields": d}

    m = _SYSLOG_RE.match(raw)
    if m:
        return {"format": "syslog", "fields": m.groupdict()}

    kv = dict((k, v.strip("\"'")) for k, v in _KV_RE.findall(raw))
    if kv:
        return {"format": "keyvalue", "fields": kv}

    return {"format": "unstructured", "raw": raw}


def parse_logs(text: str) -> dict:
    """Parse multi-line log text and summarise the detected formats."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    parsed = [parse_log_line(ln) for ln in lines]
    formats: dict[str, int] = {}
    for entry in parsed:
        formats[entry["format"]] = formats.get(entry["format"], 0) + 1
    return {"count": len(parsed), "formats": formats, "entries": parsed}


# ---------------------------------------------------------------------------
# PCAP analysis (best-effort via tshark)
# ---------------------------------------------------------------------------
def analyze_pcap(path: str, max_packets: int = 5000) -> dict:
    """Summarise a PCAP file using tshark if it is installed.

    Returns protocol-hierarchy and top-talker info. Degrades gracefully with an
    ``available: False`` result when tshark is not installed or the file is
    missing, so the caller can show a helpful message instead of crashing.
    """
    import os
    import shutil
    import subprocess

    from zorksec.utils.system import augmented_path

    if not path or not os.path.isfile(path):
        return {"available": False, "error": f"PCAP file not found: {path}"}

    tshark = shutil.which("tshark", path=augmented_path())
    if tshark is None:
        return {"available": False,
                "error": "tshark is not installed. Install it via the catalog "
                         "(SOC Utilities) to analyse PCAP files."}

    env = dict(os.environ)
    env["PATH"] = augmented_path()

    def _run(args: list[str]) -> str:
        try:
            proc = subprocess.run([tshark, *args], capture_output=True, text=True,
                                  timeout=60, check=False, env=env)
            return proc.stdout or ""
        except (subprocess.SubprocessError, OSError):
            return ""

    # Protocol hierarchy and a simple endpoint conversation count.
    proto = _run(["-r", path, "-q", "-z", "io,phs", "-c", str(max_packets)])
    talkers = _run(["-r", path, "-q", "-z", "endpoints,ip", "-c", str(max_packets)])
    return {
        "available": True,
        "file": path,
        "protocol_hierarchy": proto.strip(),
        "endpoints": talkers.strip(),
    }


# ---------------------------------------------------------------------------
# Service facade
# ---------------------------------------------------------------------------
CYBERCHEF_URL = "https://gchq.github.io/CyberChef/"
ATTACK_NAVIGATOR_URL = "https://mitre-attack.github.io/attack-navigator/"


class SocUtilsService:
    """Facade tying the SOC utility helpers together for the web/CLI layers."""

    @staticmethod
    def parse_iocs(text: str) -> dict:
        return parse_iocs(text).to_dict()

    @staticmethod
    def generate_iocs(indicators: list[str], fmt: str = "csv",
                      context: str = "") -> str:
        return generate_iocs(indicators, fmt, context)

    @staticmethod
    def parse_logs(text: str) -> dict:
        return parse_logs(text)

    @staticmethod
    def analyze_pcap(path: str) -> dict:
        return analyze_pcap(path)

    @staticmethod
    def integrations() -> dict:
        """Return links for the browser-based integrations (CyberChef, Navigator)."""
        return {
            "cyberchef": CYBERCHEF_URL,
            "attack_navigator": ATTACK_NAVIGATOR_URL,
        }
