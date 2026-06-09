"""Offline mode: detect connectivity and queue actions for later replay.

When the host is offline, installs/verifications/updates cannot run. Instead of
failing, ZorkSec queues them in ``PENDING_ACTIONS.md`` (human-readable) backed
by ``pending_actions.json`` (machine-readable). On the next online startup the
queue can be replayed with retries.
"""

from __future__ import annotations

import datetime as _dt
import json
import socket
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from zorksec.config import Settings, get_settings
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

# Action kinds.
INSTALL = "install"
VERIFY = "verify"
UPDATE = "update"
MAX_RETRIES = 3


def is_online(timeout: float = 3.0) -> bool:
    """Return True if outbound connectivity is available (DNS port probe)."""
    for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53), ("github.com", 443)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _utcnow_iso() -> str:
    return _dt.datetime.utcnow().isoformat(timespec="seconds")


@dataclass
class PendingAction:
    name: str
    command: str
    kind: str = INSTALL
    queued_at: str = field(default_factory=_utcnow_iso)
    attempts: int = 0
    state: str = "PENDING"  # PENDING | DONE | FAILED
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


class OfflineService:
    """Persisted queue of actions to run when connectivity returns."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def json_path(self) -> Path:
        return self._settings.home / "pending_actions.json"

    @property
    def markdown_path(self) -> Path:
        return self._settings.home / "PENDING_ACTIONS.md"

    # ----- persistence ------------------------------------------------------
    def _load(self) -> list[PendingAction]:
        try:
            data = json.loads(self.json_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [PendingAction(**item) for item in data]

    def _save(self, actions: list[PendingAction]) -> None:
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        self.json_path.write_text(
            json.dumps([asdict(a) for a in actions], indent=2), encoding="utf-8")
        self._render_markdown(actions)

    def _render_markdown(self, actions: list[PendingAction]) -> None:
        by_kind = {INSTALL: [], VERIFY: [], UPDATE: []}
        for a in actions:
            by_kind.setdefault(a.kind, []).append(a)
        lines = ["# ZorkSec Pending Actions",
                 f"Generated: {_utcnow_iso()}", ""]
        for kind, header in ((INSTALL, "Pending Installs"),
                             (VERIFY, "Pending Verifications"),
                             (UPDATE, "Pending Updates")):
            lines.append(f"## {header}")
            items = [a for a in by_kind.get(kind, []) if a.state == "PENDING"]
            if not items:
                lines.append("- (none)")
            for a in items:
                lines.append(f"- {a.name} | `{a.command}` | queued: {a.queued_at} "
                             f"| attempts: {a.attempts}")
            lines.append("")
        self.markdown_path.parent.mkdir(parents=True, exist_ok=True)
        self.markdown_path.write_text("\n".join(lines), encoding="utf-8")

    # ----- public API -------------------------------------------------------
    def queue_action(self, name: str, command: str, kind: str = INSTALL) -> PendingAction:
        """Add an action to the pending queue (deduplicated by name+command)."""
        actions = self._load()
        for existing in actions:
            if (existing.name == name and existing.command == command
                    and existing.state == "PENDING"):
                return existing
        action = PendingAction(name=name, command=command, kind=kind)
        actions.append(action)
        self._save(actions)
        logger.info("Queued offline %s action: %s", kind, name)
        return action

    def pending_actions(self) -> list[PendingAction]:
        return [a for a in self._load() if a.state == "PENDING"]

    def clear(self) -> None:
        self._save([])

    def process_pending(self, runner: Callable[[PendingAction], int]) -> dict:
        """Replay pending actions via ``runner`` (returns exit code).

        Each action is retried up to :data:`MAX_RETRIES` times; a 0 exit marks
        it DONE, otherwise it is marked FAILED and we continue with the next.
        """
        actions = self._load()
        done = failed = 0
        for action in actions:
            if action.state != "PENDING":
                continue
            success = False
            for _ in range(MAX_RETRIES):
                action.attempts += 1
                try:
                    code = runner(action)
                except Exception as exc:  # pragma: no cover - runner safety
                    logger.warning("Pending action %s raised: %s", action.name, exc)
                    code = 1
                if code == 0:
                    success = True
                    break
            action.state = "DONE" if success else "FAILED"
            done += int(success)
            failed += int(not success)
        self._save(actions)
        logger.info("Processed pending actions: %d done, %d failed", done, failed)
        return {"done": done, "failed": failed,
                "remaining": len(self.pending_actions())}
