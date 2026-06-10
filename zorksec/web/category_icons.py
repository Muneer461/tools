"""Map catalog category names to meaningful Font Awesome 6 (Free) icon classes.

Previously every category in the sidebar (and every tool-card logo) used the
same generic ``fa-folder`` / ``fa-shield-halved`` glyph. This module gives each
cybersecurity category a distinctive, recognisable icon from the single icon
library already bundled with the app (Font Awesome Free 6.5.1).

The mapping is keyed on the exact category strings produced by the catalog
seed (see ``RegistryService.list_categories``). Aliases for the canonical
names used in product copy (e.g. "Web Application Security") are included so
the mapping is robust if categories are renamed.
"""

from __future__ import annotations

# Exact catalog category name -> Font Awesome 6 Free icon class.
CATEGORY_ICONS: dict[str, str] = {
    # --- categories present in the shipped catalog ---
    "Information Gathering": "fa-magnifying-glass",   # search
    "Network Monitoring": "fa-satellite-dish",        # radar
    "Web Application": "fa-globe",                     # globe
    "OSINT for SOC": "fa-user-secret",                # investigator
    "Social Media OSINT": "fa-share-nodes",           # network of people
    "Malware Analysis": "fa-virus",                   # virus
    "Forensics / DFIR": "fa-microscope",              # microscope
    "Threat Hunting": "fa-crosshairs",                # target
    "Incident Response": "fa-triangle-exclamation",   # alert triangle
    "Wireless Security": "fa-wifi",                   # wifi
    "Password Auditing": "fa-key",                    # key
    "Active Directory": "fa-building",                # building
    "Exploitation": "fa-bolt",                        # lightning
    "Post Exploitation": "fa-skull",                  # post-ex
    "Log Analysis": "fa-file-lines",                  # logs
    "SIEM / Logging": "fa-gauge-high",                # SIEM dashboard
    "Phishing Analysis": "fa-envelope-open-text",     # email
    "Threat Intelligence": "fa-brain",                # intel
    "Vulnerability Scanning": "fa-bug",               # vulns
    "Reverse Engineering": "fa-gears",                # internals
    "Detection Engineering": "fa-binoculars",         # detection
    "SOC Utilities": "fa-toolbox",                    # utilities
    "Other": "fa-shapes",                             # misc

    # --- aliases / canonical product names (future-proofing) ---
    "Network Scanning": "fa-satellite-dish",
    "Web Application Security": "fa-globe",
    "OSINT": "fa-user-secret",
    "Digital Forensics": "fa-microscope",
    "Cloud Security": "fa-cloud",
    "Exploitation Frameworks": "fa-bolt",
    "Reporting": "fa-chart-line",
}

# Distinctive non-folder fallback so an unmapped category never regresses to
# the old generic folder glyph.
DEFAULT_ICON = "fa-folder-tree"


def category_icon(category: str | None) -> str:
    """Return the Font Awesome icon class for ``category`` (without ``fa-`` prefix dropped)."""
    if not category:
        return DEFAULT_ICON
    return CATEGORY_ICONS.get(category.strip(), DEFAULT_ICON)
