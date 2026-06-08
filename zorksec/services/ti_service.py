"""Threat Intelligence workspace service.

Provides:
  * curated source catalog (MISP, OpenCTI, abuse.ch, etc.) with beginner notes
  * an offline IOC classifier (ip / domain / url / hash / email)
  * indicator storage + dashboard feeds (IOC / malware / URL / domain)
  * a small offline sample feed so the dashboard is populated without network
    access or API keys; a live-fetch extension point is clearly marked.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from zorksec.repositories.feed_repository import FeedRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TiSource:
    key: str
    name: str
    category: str
    beginner_note: str
    url: str
    needs_key: bool


TI_SOURCES: list[TiSource] = [
    TiSource("misp", "MISP", "platform",
             "Open-source platform to store and share threat indicators (IOCs).",
             "https://www.misp-project.org", True),
    TiSource("opencti", "OpenCTI", "platform",
             "Organises threat knowledge using the STIX2 data model.",
             "https://www.opencti.io", True),
    TiSource("threatfox", "ThreatFox (abuse.ch)", "ioc",
             "Free feed of indicators tied to malware campaigns.",
             "https://threatfox.abuse.ch", False),
    TiSource("malwarebazaar", "MalwareBazaar (abuse.ch)", "malware",
             "Free repository of malware samples and their hashes.",
             "https://bazaar.abuse.ch", False),
    TiSource("urlhaus", "URLhaus (abuse.ch)", "url",
             "Free feed of malicious URLs used to distribute malware.",
             "https://urlhaus.abuse.ch", False),
    TiSource("otx", "AlienVault OTX", "ioc",
             "Community threat-intel feed with 'pulses' of related IOCs.",
             "https://otx.alienvault.com", True),
]

# Offline sample indicators (clearly fictitious / documentation ranges).
_SAMPLE_FEED: list[tuple[str, str, str, str]] = [
    ("urlhaus", "url", "http://malicious-example[.]test/payload.bin", "Sample malware delivery URL"),
    ("threatfox", "ioc", "203.0.113.45", "Sample C2 IP (TEST-NET-3, documentation range)"),
    ("threatfox", "domain", "evil-example[.]test", "Sample malicious domain"),
    ("malwarebazaar", "malware",
     "44d88612fea8a8f36de82e1278abb02f", "Sample MD5 (EICAR-style placeholder)"),
    ("otx", "ioc", "198.51.100.7", "Sample scanning host (documentation range)"),
]

_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def classify_indicator(value: str) -> str:
    """Best-effort offline IOC type detection. Returns ip|domain|url|hash|email|unknown."""
    raw = (value or "").strip()
    if not raw:
        return "unknown"
    # Normalise common defanging (hxxp, [.], (.) ) for classification only.
    defanged = (raw.replace("hxxp", "http").replace("[.]", ".")
                .replace("(.)", ".").replace("[:]", ":"))
    if defanged.lower().startswith(("http://", "https://")):
        return "url"
    if _EMAIL_RE.match(defanged):
        return "email"
    try:
        ipaddress.ip_address(defanged)
        return "ip"
    except ValueError:
        pass
    if defanged.isalnum() and len(defanged) in _HASH_LENGTHS:
        return "hash"
    if _DOMAIN_RE.match(defanged):
        return "domain"
    return "unknown"


def hash_kind(value: str) -> str | None:
    """Return MD5/SHA1/SHA256 for a hash-like string, else None."""
    raw = (value or "").strip()
    if raw.isalnum() and len(raw) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(raw)]
    return None


class ThreatIntelService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.feeds = FeedRepository(session)

    @staticmethod
    def sources() -> list[TiSource]:
        return list(TI_SOURCES)

    def seed_sample_feed(self) -> int:
        """Insert offline sample indicators (idempotent by indicator value)."""
        added = 0
        for source, feed_type, indicator, desc in _SAMPLE_FEED:
            if not self.feeds.exists(indicator):
                self.feeds.add_indicator(source, feed_type, indicator, desc)
                added += 1
        if added:
            logger.info("Seeded %d sample threat-intel indicators", added)
        return added

    def add_indicator(self, source: str, indicator: str, description: str = "") -> object:
        """Add an indicator, auto-classifying its feed type."""
        feed_type = classify_indicator(indicator)
        mapped = {"ip": "ioc", "domain": "domain", "url": "url",
                  "hash": "malware", "email": "ioc", "unknown": "ioc"}[feed_type]
        return self.feeds.add_indicator(source, mapped, indicator, description)

    def dashboard(self) -> dict:
        """Return counts + recent indicators grouped for the feed dashboard."""
        return {
            "counts": self.feeds.counts_by_type(),
            "ioc": self.feeds.by_type("ioc", 25),
            "malware": self.feeds.by_type("malware", 25),
            "url": self.feeds.by_type("url", 25),
            "domain": self.feeds.by_type("domain", 25),
        }

    def lookup(self, indicator: str) -> dict:
        """Classify an indicator and report whether we've seen it before."""
        ioc_type = classify_indicator(indicator)
        matches = self.feeds.search(indicator, limit=10)
        return {
            "indicator": indicator,
            "type": ioc_type,
            "hash_kind": hash_kind(indicator),
            "known": len(matches) > 0,
            "matches": [{"source": m.source, "type": m.feed_type,
                         "description": m.description} for m in matches],
        }
