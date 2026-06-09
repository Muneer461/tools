"""Help Center: answer user questions, using internet search when available.

When the host is online the service queries a public search backend (DuckDuckGo's
no-key endpoints) and returns a concise answer plus source links - similar in
spirit to asking a chat assistant, but with explicit, cited web sources. When
offline (or if the lookup fails) it falls back to a built-in local knowledge
base covering common ZorkSec/SOC questions so the Help Center is always useful.

No API keys are required. Network calls are short-timeout and fail safe.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

_USER_AGENT = "ZorkSec-HelpCenter/1.0 (+https://github.com/Muneer461/tools)"
_TIMEOUT = 6


@dataclass
class HelpAnswer:
    query: str
    answer: str
    source: str  # "web" | "local" | "offline"
    online: bool
    results: list[dict] = field(default_factory=list)  # [{title, url, snippet}]

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "answer": self.answer,
            "source": self.source,
            "online": self.online,
            "results": self.results,
        }


# ---------------------------------------------------------------------------
# Local knowledge base (offline fallback). Keyword -> answer.
# ---------------------------------------------------------------------------
_LOCAL_KB: list[tuple[tuple[str, ...], str]] = [
    (("command not found", "not found", "path"),
     "If a tool shows 'command not found' after install, its binary is likely "
     "in a per-user bin dir not on your PATH. Add this to ~/.bashrc and open a "
     "new terminal:\n  export PATH=\"$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH\"\n"
     "Or run the Kali Diagnostics 'PATH exports' auto-fix."),
    (("dpkg", "apt", "broken", "lock", "could not get lock"),
     "For broken apt/dpkg state on Kali, run:\n"
     "  sudo dpkg --configure -a\n  sudo apt-get -f install\n  sudo apt-get update\n"
     "If you see 'Could not get lock', no apt must be running, then remove "
     "/var/lib/dpkg/lock*. The Kali Diagnostics tab can do this automatically."),
    (("terminal", "loading", "connecting", "blank"),
     "If the in-browser terminal stays on 'loading/connecting', the browser "
     "may be blocking the realtime connection or cannot reach the xterm.js CDN. "
     "Connect to the internet and reload, or use the 'Native Kali terminal' "
     "option from the Run menu (works offline)."),
    (("password", "reset", "forgot", "login"),
     "Default login is zorksec / zorksec and you must change it on first login. "
     "Forgot it? Use 'Recovery question' on the dashboard, or the Forgot Password "
     "page, which asks your security question."),
    (("sigma", "detection"),
     "Sigma is a generic signature format for SIEM detections. Write rules in "
     "YAML and convert them to your SIEM's query language with sigma-cli/pySigma. "
     "ZorkSec includes Sigma and pySigma in the Detection Engineering category."),
    (("ioc", "indicator"),
     "IOCs (Indicators of Compromise) are artefacts like IPs, domains, URLs, "
     "hashes and emails. Use the SOC Utilities IOC parser to extract and refang "
     "them from text, and the generator to export CSV/STIX/defanged lists."),
    (("mitre", "att&ck", "attack"),
     "MITRE ATT&CK is a knowledge base of adversary tactics and techniques. Use "
     "the ATT&CK tab to see which techniques your installed tools help detect or "
     "emulate, and the ATT&CK Navigator integration to build coverage heatmaps."),
]


def _local_answer(query: str) -> str:
    q = query.lower()
    for keywords, answer in _LOCAL_KB:
        if any(k in q for k in keywords):
            return answer
    return ("I could not reach the internet to search, and I have no offline "
            "entry for that. Try rephrasing, or check the Diagnostic Center / "
            "Kali Diagnostics tabs for environment problems.")


def is_online(timeout: float = 3.0) -> bool:
    """Best-effort connectivity probe (DNS port to public resolvers)."""
    import socket
    for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _http_get_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:  # network, JSON, timeout - all fail safe
        logger.info("Help search HTTP error: %s", exc)
        return None


def _search_web(query: str) -> tuple[str, list[dict]]:
    """Query DuckDuckGo's Instant Answer API (no key). Returns (answer, results)."""
    encoded = urllib.parse.quote(query)
    url = (f"https://api.duckduckgo.com/?q={encoded}"
           "&format=json&no_html=1&skip_disambig=1&t=zorksec")
    data = _http_get_json(url)
    if not data:
        return "", []

    answer = (data.get("AbstractText") or data.get("Answer") or "").strip()
    results: list[dict] = []

    abstract_url = data.get("AbstractURL")
    if answer and abstract_url:
        results.append({"title": data.get("Heading", "Source"),
                        "url": abstract_url, "snippet": answer[:200]})

    def _walk_topics(topics: list) -> None:
        for item in topics:
            if len(results) >= 6:
                return
            if isinstance(item, dict) and item.get("Topics"):
                _walk_topics(item["Topics"])
            elif isinstance(item, dict) and item.get("FirstURL"):
                results.append({
                    "title": (item.get("Text", "")[:80] or "Result"),
                    "url": item["FirstURL"],
                    "snippet": item.get("Text", "")[:200],
                })

    _walk_topics(data.get("RelatedTopics", []))

    if not answer and results:
        answer = results[0]["snippet"]
    return answer, results


class HelpCenterService:
    """Answer help queries with web search + cited sources, offline fallback."""

    def ask(self, query: str) -> HelpAnswer:
        query = (query or "").strip()
        if not query:
            return HelpAnswer(query, "Please enter a question.", "local", is_online())

        online = is_online()
        if online:
            answer, results = _search_web(query)
            if answer or results:
                if not answer:
                    answer = "Here are the most relevant sources I found:"
                return HelpAnswer(query, answer, "web", True, results)
            # Online but search returned nothing useful -> local KB.
            return HelpAnswer(query, _local_answer(query), "local", True)

        # Offline: use the built-in knowledge base.
        return HelpAnswer(query, _local_answer(query), "offline", False)
