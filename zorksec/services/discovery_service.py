"""Tool discovery: detect what is already installed on the host.

Two layers:
  * :meth:`sync_installed_status` - cheap PATH lookup (``shutil.which``) that
    updates ``tool_status.installed`` for catalog tools.
  * package-manager probes (apt/snap/pip/go/cargo/docker) - best-effort
    enumeration used by the dashboard "detected tools" panel.

All package-manager calls are defensive: a missing manager simply yields an
empty list rather than raising.
"""

from __future__ import annotations

import datetime as _dt
import shutil
import subprocess
from dataclasses import dataclass

from sqlalchemy.orm import Session

from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

# Catalog binary -> catalog slug is resolved at runtime; here we keep the raw
# detection helpers independent of the catalog.


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _run(cmd: list[str], timeout: int = 15) -> str:
    """Run a command, returning stdout or '' on any failure."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return ""


def binary_present(binary: str) -> bool:
    """True if an executable is on PATH."""
    return bool(binary) and shutil.which(binary) is not None


@dataclass
class PackageScan:
    manager: str
    available: bool
    packages: list[str]


class DiscoveryService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.tools = ToolRepository(session)

    # ----- catalog installed-state sync ------------------------------------
    def sync_installed_status(self) -> int:
        """Update installed flags for catalog tools that declare a binary.

        Returns the number of tools currently detected as installed.
        """
        installed = 0
        now = _utcnow()
        from zorksec.registry.catalog import CATALOG  # local import avoids cycle

        binary_by_slug = {d.slug: d.check_binary for d in CATALOG}
        for tool in self.tools.list():
            binary = binary_by_slug.get(tool.slug, "")
            status = self.tools.ensure_status(tool)
            status.last_checked_at = now
            if binary:
                status.installed = binary_present(binary)
                if status.installed:
                    installed += 1
            # tools without a detectable binary keep their stored state
        self.session.flush()
        logger.info("Discovery sync: %d catalog tools detected as installed", installed)
        return installed

    # ----- package-manager probes ------------------------------------------
    def scan_apt(self) -> PackageScan:
        if not binary_present("dpkg-query"):
            return PackageScan("apt", False, [])
        out = _run(["dpkg-query", "-W", "-f=${Package}\n"])
        pkgs = [line.strip() for line in out.splitlines() if line.strip()]
        return PackageScan("apt", True, pkgs)

    def scan_snap(self) -> PackageScan:
        if not binary_present("snap"):
            return PackageScan("snap", False, [])
        out = _run(["snap", "list"])
        lines = out.splitlines()[1:]  # skip header
        pkgs = [line.split()[0] for line in lines if line.strip()]
        return PackageScan("snap", True, pkgs)

    def scan_pip(self) -> PackageScan:
        if not binary_present("pip3") and not binary_present("pip"):
            return PackageScan("pip", False, [])
        binary = "pip3" if binary_present("pip3") else "pip"
        out = _run([binary, "list", "--format=freeze"])
        pkgs = [line.split("==")[0] for line in out.splitlines() if "==" in line]
        return PackageScan("pip", True, pkgs)

    def scan_docker(self) -> PackageScan:
        if not binary_present("docker"):
            return PackageScan("docker", False, [])
        out = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
        pkgs = [line.strip() for line in out.splitlines() if line.strip()]
        return PackageScan("docker", True, pkgs)

    def scan_all(self) -> list[PackageScan]:
        return [self.scan_apt(), self.scan_snap(), self.scan_pip(), self.scan_docker()]
