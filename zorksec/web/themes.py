"""Team theme engine.

``zorksec.css`` is written against a set of CSS custom properties (the
``--purple-primary`` / ``--cyan-primary`` / ``--bg-primary`` family). The team
selector therefore only needs to override those variables to re-skin the
entire UI - sidebar, cards, buttons, borders, header, modals, terminal accent,
and the diagnostics dashboard all read from them.

Previously only three legacy aliases (``--accent`` / ``--bg`` / ``--panel``)
were overridden, which is why selecting "Red Team" changed the dropdown but
left the dashboard blue/purple. Each palette below provides the full variable
set so a theme switch updates the whole application.

Each palette is a flat mapping of CSS variable name -> value, emitted into a
``:root`` block by ``base.html``.
"""

from __future__ import annotations

# Canonical team keys understood throughout the app.
TEAMS = ("blue", "red", "both")
DEFAULT_TEAM = "both"

# Human-friendly names (kept in sync with the legacy THEMES dict in app.py).
TEAM_NAMES = {
    "blue": "Blue Team",
    "red": "Red Team",
    "both": "Purple (Both)",
}


def _palette(*, primary, secondary, dark, accent2, accent2b,
             bg1, bg2, card, card_hover, border, border_glow, name) -> dict:
    """Build a full CSS-variable palette from a small set of seed colours."""
    return {
        "name": name,
        # Primary accent family (was the purple group).
        "--purple-primary": primary,
        "--purple-secondary": secondary,
        "--purple-dark": dark,
        # Secondary accent family (was the cyan group).
        "--cyan-primary": accent2,
        "--cyan-secondary": accent2b,
        # Backgrounds / surfaces.
        "--bg-primary": bg1,
        "--bg-secondary": bg2,
        "--bg-card": card,
        "--bg-card-hover": card_hover,
        "--border-color": border,
        "--border-glow": border_glow,
        # Legacy aliases still referenced by older partials.
        "--accent": primary,
        "--bg": bg1,
        "--panel": card,
    }


THEME_PALETTES: dict[str, dict] = {
    # Purple Team (hybrid: detection + attack simulation) - the default look.
    "both": _palette(
        name="Purple (Both)",
        primary="#805aff", secondary="#a78bfa", dark="#6344cc",
        accent2="#00d4ff", accent2b="#48dbfb",
        bg1="#0a0a1a", bg2="#0d0d24",
        card="rgba(20, 20, 55, 0.7)", card_hover="rgba(30, 30, 70, 0.8)",
        border="rgba(128, 90, 255, 0.15)", border_glow="rgba(128, 90, 255, 0.4)",
    ),
    # Blue Team (SOC analyst: Splunk / Sentinel / Wazuh feel).
    "blue": _palette(
        name="Blue Team",
        primary="#2f81f7", secondary="#58a6ff", dark="#1f6feb",
        accent2="#22d3ee", accent2b="#67e8f9",
        bg1="#070d1b", bg2="#0b1326",
        card="rgba(15, 30, 60, 0.72)", card_hover="rgba(22, 42, 80, 0.82)",
        border="rgba(47, 129, 247, 0.18)", border_glow="rgba(47, 129, 247, 0.45)",
    ),
    # Red Team (offensive security / adversary simulation).
    "red": _palette(
        name="Red Team",
        primary="#ff3b4e", secondary="#ff6b7a", dark="#c41e2f",
        accent2="#ff8a3d", accent2b="#ffb86b",
        bg1="#14070a", bg2="#1d0a0e",
        card="rgba(60, 16, 22, 0.72)", card_hover="rgba(82, 22, 30, 0.82)",
        border="rgba(255, 59, 78, 0.20)", border_glow="rgba(255, 59, 78, 0.5)",
    ),
}


def normalize_team(team: str | None) -> str:
    """Return a valid team key, defaulting to the purple/both theme."""
    if team in THEME_PALETTES:
        return team  # type: ignore[return-value]
    return DEFAULT_TEAM


def theme_vars(team: str | None) -> dict:
    """Return the full CSS-variable palette for a team (safe for any input)."""
    return THEME_PALETTES[normalize_team(team)]
