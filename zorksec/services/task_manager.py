"""Background task manager for long-running installs/commands.

Runs shell command sequences off the main thread so the TUI/web UI never
freezes. Each task carries a lifecycle state and per-command wall-clock
timeouts; on timeout (or cancel) the whole process group is killed so no
orphaned ``apt``/``go``/``git`` child keeps running.

Public API (thread-safe):
    submit(title, commands, timeout=None) -> task_id
    status(task_id) -> TaskStatus | None
    cancel(task_id) -> bool
    list_all() -> list[TaskStatus]
"""

from __future__ import annotations

import datetime as _dt
import os
import signal
import subprocess
import threading
import uuid
from dataclasses import dataclass, field

from zorksec.utils.logging import get_logger
from zorksec.utils.system import tool_env

logger = get_logger(__name__)

# Task states.
QUEUED = "QUEUED"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
CANCELLED = "CANCELLED"
TIMEOUT = "TIMEOUT"

DEFAULT_TASK_TIMEOUT = 180


def _utcnow() -> _dt.datetime:
    return _dt.datetime.utcnow()


@dataclass
class TaskStatus:
    task_id: str
    title: str
    commands: list[str]
    state: str = QUEUED
    started_at: _dt.datetime | None = None
    finished_at: _dt.datetime | None = None
    exit_code: int | None = None
    stdout_log: str = ""
    stderr_log: str = ""

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "commands": self.commands,
            "state": self.state,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "exit_code": self.exit_code,
            "stdout_log": self.stdout_log,
            "stderr_log": self.stderr_log,
        }


class TaskManager:
    """Thread-safe manager that runs command sequences as background tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskStatus] = {}
        self._procs: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    # ----- public API -------------------------------------------------------
    def submit(self, title: str, commands: list[str],
               timeout: int | None = None) -> str:
        """Queue a sequence of shell commands and start running them.

        Returns a ``task_id`` immediately; the work runs on a daemon thread.
        """
        task_id = uuid.uuid4().hex[:12]
        status = TaskStatus(task_id=task_id, title=title, commands=list(commands))
        with self._lock:
            self._tasks[task_id] = status
        thread = threading.Thread(
            target=self._run, args=(task_id, timeout or DEFAULT_TASK_TIMEOUT),
            name=f"task-{task_id}", daemon=True)
        with self._lock:
            self._threads[task_id] = thread
        thread.start()
        logger.info("Task %s submitted: %s", task_id, title)
        return task_id

    def status(self, task_id: str) -> TaskStatus | None:
        with self._lock:
            return self._tasks.get(task_id)

    def list_all(self) -> list[TaskStatus]:
        with self._lock:
            return list(self._tasks.values())

    def cancel(self, task_id: str) -> bool:
        """Cancel a queued or running task. Returns True if a cancel was applied."""
        with self._lock:
            status = self._tasks.get(task_id)
            if status is None or status.state in (COMPLETED, FAILED, CANCELLED, TIMEOUT):
                return False
            self._cancelled.add(task_id)
            proc = self._procs.get(task_id)
            if status.state == QUEUED:
                status.state = CANCELLED
                status.finished_at = _utcnow()
        # Kill outside the lock to avoid holding it during signal handling.
        if proc is not None:
            _kill_group(proc)
        logger.info("Task %s cancel requested", task_id)
        return True

    def wait(self, task_id: str, timeout: float | None = None) -> TaskStatus | None:
        """Block until a task's worker thread finishes (test/CLI convenience)."""
        with self._lock:
            thread = self._threads.get(task_id)
        if thread is not None:
            thread.join(timeout)
        return self.status(task_id)

    # ----- worker -----------------------------------------------------------
    def _run(self, task_id: str, timeout: int) -> None:
        status = self.status(task_id)
        if status is None:
            return
        with self._lock:
            if task_id in self._cancelled:
                status.state = CANCELLED
                status.finished_at = _utcnow()
                return
            status.state = RUNNING
            status.started_at = _utcnow()

        out_chunks: list[str] = []
        final_code = 0
        for command in status.commands:
            with self._lock:
                if task_id in self._cancelled:
                    status.state = CANCELLED
                    break
            code, output, timed_out = self._run_one(task_id, command, timeout)
            out_chunks.append(output)
            final_code = code
            if timed_out:
                status.state = TIMEOUT
                break
            with self._lock:
                if task_id in self._cancelled:
                    status.state = CANCELLED
                    break
            if code != 0:
                status.state = FAILED
                break
        else:
            # Loop completed without break -> all commands succeeded.
            status.state = COMPLETED

        with self._lock:
            status.exit_code = final_code
            status.stdout_log = "\n".join(out_chunks)
            status.finished_at = _utcnow()
            self._procs.pop(task_id, None)
        logger.info("Task %s finished: state=%s code=%s",
                    task_id, status.state, final_code)

    def _run_one(self, task_id: str, command: str,
                 timeout: int) -> tuple[int, str, bool]:
        """Run a single shell command with a watchdog timeout."""
        try:
            proc = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, env=tool_env(),
                start_new_session=True)
        except (OSError, ValueError) as exc:
            return 1, f"failed to start: {exc}", False

        with self._lock:
            self._procs[task_id] = proc

        timed_out = {"flag": False}

        def _on_timeout() -> None:
            timed_out["flag"] = True
            _kill_group(proc)

        watchdog = threading.Timer(timeout, _on_timeout)
        watchdog.daemon = True
        watchdog.start()
        try:
            output, _ = proc.communicate()
        finally:
            watchdog.cancel()
        return proc.returncode if proc.returncode is not None else 1, output or "", timed_out["flag"]


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM then SIGKILL the process's whole group."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass


# A module-level singleton is convenient for the web/TUI layers.
_MANAGER: TaskManager | None = None


def get_task_manager() -> TaskManager:
    """Return the process-wide TaskManager singleton."""
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = TaskManager()
    return _MANAGER
