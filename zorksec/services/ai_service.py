"""AI assistant service.

Default mode is fully offline: a deterministic keyword responder that explains
common SOC concepts in beginner language. If the user configures an API key
for a provider (stored encrypted via :class:`SecretBox`), the service can be
extended to call that provider - the key plumbing and storage are implemented
here; the network call is left as a clearly-marked extension point so the
platform works with zero external dependencies out of the box.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import ApiKey
from zorksec.security.crypto import SecretBox
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

SUPPORTED_PROVIDERS = ["openai", "anthropic", "gemini", "openrouter", "ollama"]

# Beginner-friendly canned explanations keyed by topic.
_KNOWLEDGE: dict[str, str] = {
    "phishing": (
        "Phishing is a fraudulent message (often email) that tries to trick someone "
        "into revealing credentials or running malware. Triage tips: check the sender "
        "domain, hover links before clicking, look for urgency/extortion language, and "
        "detonate attachments only in an isolated sandbox."
    ),
    "ioc": (
        "An IOC (Indicator of Compromise) is an artifact that suggests a breach - e.g. "
        "a malicious IP, domain, file hash, or URL. Enrich IOCs with threat-intel "
        "sources (VirusTotal, abuse.ch) before acting, and record context (where it "
        "was seen) in your case notes."
    ),
    "log": (
        "When reading a log line, identify: timestamp, source host/user, the action, "
        "and the outcome (success/failure). Correlate unusual actions across time and "
        "hosts. Failed-then-successful logins, new admin accounts, and odd process "
        "trees are classic red flags."
    ),
    "sigma": (
        "Sigma is a vendor-neutral detection rule format (YAML). A rule has a logsource "
        "(what data) and a detection (conditions). You convert it to your SIEM's query "
        "language with a Sigma backend. Great for sharing detections across teams."
    ),
    "incident": (
        "Incident response follows: Prepare, Identify, Contain, Eradicate, Recover, and "
        "Lessons Learned (PICERL). For an L1 analyst, focus on accurate identification "
        "and timely escalation with clear, factual notes."
    ),
    "attack": (
        "MITRE ATT&CK is a knowledge base of real-world adversary behaviour, organised "
        "into Tactics (the goal, e.g. 'Persistence') and Techniques (how, e.g. T1547 "
        "'Boot or Logon Autostart'). Mapping detections to ATT&CK shows your coverage."
    ),
}

_DEFAULT_REPLY = (
    "I'm the offline ZorkSec assistant. Ask me about phishing, IOCs, reading logs, "
    "Sigma rules, incident response, or MITRE ATT&CK. (Configure an API key in "
    "Settings to enable a full LLM provider.)"
)


@dataclass
class AiReply:
    text: str
    source: str  # "offline" | provider name


class AiService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self._box = SecretBox()

    # ----- key management ---------------------------------------------------
    def set_key(self, user_id: int, provider: str, raw_key: str) -> None:
        provider = provider.lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported provider '{provider}'.")
        encrypted = self._box.encrypt(raw_key)
        existing = self.session.execute(
            select(ApiKey).where(ApiKey.user_id == user_id, ApiKey.provider == provider)
        ).scalar_one_or_none()
        if existing:
            existing.encrypted_key = encrypted
        else:
            self.session.add(ApiKey(user_id=user_id, provider=provider, encrypted_key=encrypted))
        self.session.flush()
        logger.info("Stored encrypted API key for provider '%s'", provider)

    def has_key(self, user_id: int, provider: str) -> bool:
        return self._get_key(user_id, provider.lower()) is not None

    def configured_providers(self, user_id: int) -> list[str]:
        rows = self.session.execute(
            select(ApiKey.provider).where(ApiKey.user_id == user_id)
        ).scalars().all()
        return list(rows)

    def _get_key(self, user_id: int, provider: str) -> str | None:
        row = self.session.execute(
            select(ApiKey).where(ApiKey.user_id == user_id, ApiKey.provider == provider)
        ).scalar_one_or_none()
        if row is None:
            return None
        return self._box.decrypt(row.encrypted_key)

    # ----- assistant --------------------------------------------------------
    def ask(self, prompt: str, user_id: int | None = None,
            provider: str | None = None) -> AiReply:
        """Answer a question. Uses the offline responder unless a provider key
        is configured (provider call is an extension point)."""
        if provider and user_id is not None and self.has_key(user_id, provider):
            # Extension point: a real implementation would call the provider API
            # here using self._get_key(...). We keep the offline answer to avoid
            # any network dependency in the base platform.
            offline = self._offline_answer(prompt)
            return AiReply(text=offline, source=f"{provider} (key configured; "
                          "offline fallback in base build)")
        return AiReply(text=self._offline_answer(prompt), source="offline")

    @staticmethod
    def _offline_answer(prompt: str) -> str:
        text = (prompt or "").lower()
        for keyword, answer in _KNOWLEDGE.items():
            if keyword in text:
                return answer
        return _DEFAULT_REPLY
