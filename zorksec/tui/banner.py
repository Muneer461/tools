"""ASCII banner and security quotes for the TUI."""

from __future__ import annotations

import random

from zorksec import __author__, __version__
from zorksec.utils.system import host_facts

_BANNER = r"""
 ______          _     ____
|__  / ___  _ __| | __/ ___|  ___  ___
  / / / _ \| '__| |/ /\___ \ / _ \/ __|
 / /_| (_) | |  |   <  ___) |  __/ (__
/____|\___/|_|  |_|\_\|____/ \___|\___|
"""

_QUOTES = [
    "Defense is a process, not a product.",
    "Logs you don't read are logs you don't have.",
    "Assume breach; verify everything.",
    "The quieter you become, the more you are able to hear.",
    "Every alert is a question, not an answer.",
    "Patch fast, hunt faster.",
    "Trust, but verify - then verify again.",
]


def render_banner_text() -> str:
    """Return the full banner as plain text (used by tests and the TUI)."""
    facts = host_facts()
    quote = random.choice(_QUOTES)
    lines = [
        _BANNER,
        "        ZorkSec - SOC L1 Learning Edition",
        f"        v{__version__}  |  {__author__}",
        "",
        f"  OS     : {facts['os']}",
        f"  Kernel : {facts['kernel']}   Arch: {facts['arch']}",
        f"  Host   : {facts['hostname']}   IP: {facts['ip']}",
        f"  User   : {facts['user']}   Python: {facts['python']}",
        "",
        f'  "{quote}"',
    ]
    return "\n".join(lines)
