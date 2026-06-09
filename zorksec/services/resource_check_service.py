"""High-resource install warnings.

Some catalog tools are full platforms (Elastic, Wazuh, MISP, OpenCTI, …) that
need significant RAM/CPU/disk and can take many minutes to deploy. Before
installing one of these we show a warning comparing the tool's requirements to
the host's available resources and require an explicit ``YES`` confirmation.

This module is pure/standalone (no DB) so it is easy to unit-test and can be
called from the executor, the web API, and the CLI alike.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceProfile:
    """Approximate resource requirements for a heavy tool."""

    ram_gb: float
    cpu_cores: int
    disk_gb: float
    minutes: int


# Keyed by catalog slug. Values mirror the documented ZorkSec heavy-tool table.
# Tools not present here are treated as "light" and need no confirmation.
HEAVY_TOOLS: dict[str, ResourceProfile] = {
    "elastic": ResourceProfile(8, 4, 20, 15),
    "elasticsearch": ResourceProfile(8, 4, 20, 15),
    "wazuh": ResourceProfile(4, 2, 10, 20),
    "misp": ResourceProfile(4, 2, 15, 30),
    "opencti": ResourceProfile(8, 4, 20, 30),
    "thehive": ResourceProfile(4, 2, 10, 15),
    "timesketch": ResourceProfile(8, 4, 20, 25),
    "helk": ResourceProfile(16, 4, 30, 45),
    "security-onion": ResourceProfile(16, 4, 100, 60),
    "cuckoo": ResourceProfile(4, 2, 50, 30),
    "cape": ResourceProfile(4, 2, 50, 30),
    "velociraptor": ResourceProfile(2, 2, 5, 10),
    "caldera": ResourceProfile(2, 2, 5, 10),
    "arkime": ResourceProfile(4, 2, 20, 15),
    "zeek": ResourceProfile(2, 2, 5, 10),
    "suricata": ResourceProfile(2, 2, 5, 10),
}


@dataclass(frozen=True)
class SystemResources:
    ram_total_gb: float
    ram_available_gb: float
    disk_total_gb: float
    disk_free_gb: float
    cpu_cores: int


@dataclass
class ResourceWarning:
    slug: str
    profile: ResourceProfile
    system: SystemResources
    sufficient: bool
    shortfalls: list[str]

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "required": {
                "ram_gb": self.profile.ram_gb,
                "cpu_cores": self.profile.cpu_cores,
                "disk_gb": self.profile.disk_gb,
                "minutes": self.profile.minutes,
            },
            "available": {
                "ram_available_gb": round(self.system.ram_available_gb, 1),
                "disk_free_gb": round(self.system.disk_free_gb, 1),
                "cpu_cores": self.system.cpu_cores,
            },
            "sufficient": self.sufficient,
            "shortfalls": self.shortfalls,
            "box": self.render_box(),
        }

    def render_box(self) -> str:
        """Return the ASCII confirmation box shown before a heavy install."""
        p, s = self.profile, self.system
        lines = [
            "+--------------------------------------------+",
            "|  HIGH RESOURCE WARNING                     |",
            "|                                            |",
            f"|  Tool:          {self.slug:<26}|",
            f"|  RAM required:  {str(p.ram_gb) + ' GB':<26}|",
            f"|  CPU cores:     {str(p.cpu_cores):<26}|",
            f"|  Disk space:    {str(p.disk_gb) + ' GB':<26}|",
            f"|  Est. install:  {str(p.minutes) + ' min':<26}|",
            "|                                            |",
            f"|  RAM available: {f'{s.ram_available_gb:.1f} GB':<26}|",
            f"|  Disk free:     {f'{s.disk_free_gb:.1f} GB':<26}|",
            "|                                            |",
            "|  Type YES to continue or n to cancel       |",
            "+--------------------------------------------+",
        ]
        return "\n".join(lines)


def system_resources() -> SystemResources:
    """Read host RAM/disk/CPU (best-effort; degrades without psutil)."""
    cpu_cores = os.cpu_count() or 1
    try:
        usage = shutil.disk_usage("/")
        disk_total = usage.total / (1024 ** 3)
        disk_free = usage.free / (1024 ** 3)
    except OSError:
        disk_total = disk_free = 0.0

    ram_total = ram_available = 0.0
    try:
        import psutil  # type: ignore

        mem = psutil.virtual_memory()
        ram_total = mem.total / (1024 ** 3)
        ram_available = mem.available / (1024 ** 3)
    except Exception:
        # Fallback for Linux without psutil: read /proc/meminfo.
        try:
            info: dict[str, int] = {}
            with open("/proc/meminfo", encoding="utf-8") as fh:
                for line in fh:
                    key, _, rest = line.partition(":")
                    info[key.strip()] = int(rest.strip().split()[0])  # kB
            ram_total = info.get("MemTotal", 0) / (1024 ** 2)
            ram_available = info.get("MemAvailable", info.get("MemFree", 0)) / (1024 ** 2)
        except (OSError, ValueError):
            pass

    return SystemResources(
        ram_total_gb=ram_total,
        ram_available_gb=ram_available,
        disk_total_gb=disk_total,
        disk_free_gb=disk_free,
        cpu_cores=cpu_cores,
    )


class ResourceCheckService:
    """Decides whether a tool needs a high-resource confirmation, and builds it."""

    @staticmethod
    def profile_for(slug: str) -> ResourceProfile | None:
        return HEAVY_TOOLS.get(slug)

    @staticmethod
    def requires_confirmation(slug: str) -> bool:
        """True when installing ``slug`` should prompt for a YES confirmation."""
        return slug in HEAVY_TOOLS

    @classmethod
    def warning_for(cls, slug: str) -> ResourceWarning | None:
        """Build the resource warning for a heavy tool (None if not heavy)."""
        profile = cls.profile_for(slug)
        if profile is None:
            return None
        system = system_resources()
        shortfalls: list[str] = []
        # Only compare when we could actually read the figure (>0).
        if system.ram_available_gb and system.ram_available_gb < profile.ram_gb:
            shortfalls.append(
                f"RAM: need {profile.ram_gb} GB, have "
                f"{system.ram_available_gb:.1f} GB available")
        if system.disk_free_gb and system.disk_free_gb < profile.disk_gb:
            shortfalls.append(
                f"Disk: need {profile.disk_gb} GB, have "
                f"{system.disk_free_gb:.1f} GB free")
        if system.cpu_cores and system.cpu_cores < profile.cpu_cores:
            shortfalls.append(
                f"CPU: recommend {profile.cpu_cores} cores, have {system.cpu_cores}")
        return ResourceWarning(
            slug=slug, profile=profile, system=system,
            sufficient=not shortfalls, shortfalls=shortfalls)

    @staticmethod
    def confirms(answer: str) -> bool:
        """Only an exact uppercase 'YES' proceeds (per spec)."""
        return answer == "YES"
