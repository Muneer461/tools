"""Usage / documentation helper for tools.

Powers the "open docs/usage in a new tab" feature. For any tool - whether it is
in the ZorkSec catalog, pre-installed on Kali, or installed manually by the
user - this produces:
  * the official documentation URL (from the catalog when known)
  * a beginner explanation (from the catalog when known)
  * live, locally-generated usage text by running ``<binary> --help`` (and
    falling back to ``-h`` / ``man``), captured safely.

It also provides :func:`launch_native_terminal`, which opens a real Kali
terminal emulator running a tool (the "redirect to Kali terminal" option),
degrading gracefully on headless hosts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass

from zorksec.utils.logging import get_logger
from zorksec.utils.system import augmented_path, tool_env

logger = get_logger(__name__)


@dataclass
class UsageInfo:
    slug: str
    name: str
    binary: str
    found: bool
    docs_url: str
    beginner_note: str
    usage_text: str
    source: str  # "--help" | "-h" | "man" | "none"

    def to_dict(self) -> dict:
        return asdict(self)


def _capture(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    """Run a command capturing combined output; never raises."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            check=False, env=tool_env(),
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def _resolve_binary(slug: str, tool) -> str:
    """Best-effort binary name for a tool."""
    # Prefer the catalog's declared check_binary.
    try:
        from zorksec.registry.catalog import CATALOG
        for d in CATALOG:
            if d.slug == slug and d.check_binary:
                return d.check_binary
    except Exception:
        pass
    # Fall back to the tool's run command's first token, or the slug itself.
    if tool is not None and getattr(tool, "run_command", ""):
        first = tool.run_command.split()[0]
        return os.path.basename(first)
    return slug


def _live_usage(binary: str) -> tuple[str, str]:
    """Return (usage_text, source) by trying --help, then -h, then man."""
    if not binary or shutil.which(binary, path=augmented_path()) is None:
        return ("", "none")
    for args, source in (([binary, "--help"], "--help"), ([binary, "-h"], "-h")):
        code, out = _capture(args)
        if out.strip():
            return (out.strip()[:8000], source)
    # man page as a last resort (rendered to plain text).
    if shutil.which("man"):
        code, out = _capture(["man", binary])
        if out.strip():
            return (out.strip()[:8000], "man")
    return ("", "none")


class UsageService:
    @staticmethod
    def usage_for(tool, binary_override: str = "", slug_override: str = "") -> dict:
        """Build a UsageInfo dict for a catalog tool or a raw binary name."""
        slug = getattr(tool, "slug", "") or slug_override or binary_override
        name = getattr(tool, "name", "") or binary_override or slug
        docs = getattr(tool, "docs_url", "") or ""
        note = getattr(tool, "beginner_note", "") or ""
        binary = binary_override or _resolve_binary(slug, tool)
        usage_text, source = _live_usage(binary)
        found = source != "none"
        if not found and not usage_text:
            usage_text = (f"'{binary}' is not installed or not on PATH yet.\n"
                          "Install it first, then reopen this page to see its usage.")
        return UsageInfo(
            slug=slug, name=name, binary=binary, found=found,
            docs_url=docs, beginner_note=note, usage_text=usage_text, source=source,
        ).to_dict()


# Common desktop terminal emulators on Kali / Linux, in preference order.
_TERMINALS = [
    ("qterminal", ["qterminal", "-e"]),
    ("x-terminal-emulator", ["x-terminal-emulator", "-e"]),
    ("gnome-terminal", ["gnome-terminal", "--"]),
    ("konsole", ["konsole", "-e"]),
    ("xfce4-terminal", ["xfce4-terminal", "-x"]),
    ("xterm", ["xterm", "-e"]),
]


def launch_native_terminal(argv: list[str], shell: bool, cwd: str | None) -> tuple[bool, str]:
    """Open a native Kali terminal running the given command.

    Returns (launched, detail). On a headless host (no DISPLAY / no terminal
    emulator) returns (False, reason) so the caller can fall back to the
    browser terminal.
    """
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return (False, "No graphical display detected; use the in-browser terminal instead.")

    # Compose the command the terminal should run, keeping it open afterwards.
    if shell:
        inner = argv[0]
    else:
        import shlex
        inner = " ".join(shlex.quote(a) for a in argv)
    # Run the tool, then drop into an interactive shell so output stays visible.
    bash_c = f"{inner}; echo; echo '[ZorkSec] command finished - press Ctrl+D to close'; exec bash"

    for name, prefix in _TERMINALS:
        if shutil.which(name):
            try:
                subprocess.Popen(
                    [*prefix, "bash", "-lc", bash_c],
                    cwd=cwd, env=tool_env(),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                return (True, f"Launched in {name}.")
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("Failed to launch %s: %s", name, exc)
                continue
    return (False, "No supported terminal emulator found on this host.")
