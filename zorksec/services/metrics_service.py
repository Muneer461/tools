"""Host metrics for the SOC dashboard widgets (CPU / RAM / disk / uptime).

Uses ``psutil`` when available and degrades gracefully to ``unknown`` values
so the dashboard never crashes on a minimal host.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass


@dataclass
class SystemMetrics:
    cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    memory_total_mb: int
    disk_percent: float
    uptime_seconds: int
    available: bool

    def to_dict(self) -> dict:
        return asdict(self)


class MetricsService:
    def collect(self) -> SystemMetrics:
        try:
            import psutil  # type: ignore
        except ImportError:
            return SystemMetrics(0.0, 0.0, 0, 0, 0.0, 0, available=False)

        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        uptime = int(time.time() - psutil.boot_time())
        return SystemMetrics(
            cpu_percent=round(psutil.cpu_percent(interval=0.0), 1),
            memory_percent=round(mem.percent, 1),
            memory_used_mb=int(mem.used / 1_048_576),
            memory_total_mb=int(mem.total / 1_048_576),
            disk_percent=round(disk.percent, 1),
            uptime_seconds=uptime,
            available=True,
        )
