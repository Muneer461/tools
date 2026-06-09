"""Tests for the background task manager."""

from __future__ import annotations

import time

from zorksec.services.task_manager import (
    CANCELLED,
    COMPLETED,
    FAILED,
    TIMEOUT,
    TaskManager,
    get_task_manager,
)


def test_successful_task_completes():
    tm = TaskManager()
    tid = tm.submit("ok", ["echo hello", "echo world"])
    status = tm.wait(tid, 5)
    assert status.state == COMPLETED
    assert status.exit_code == 0
    assert "hello" in status.stdout_log and "world" in status.stdout_log


def test_failing_command_stops_sequence():
    tm = TaskManager()
    tid = tm.submit("fail", ["false", "echo should-not-appear"])
    status = tm.wait(tid, 5)
    assert status.state == FAILED
    assert "should-not-appear" not in status.stdout_log


def test_timeout_marks_task_timeout():
    tm = TaskManager()
    start = time.time()
    tid = tm.submit("slow", ["sleep 30 & wait"], timeout=2)
    status = tm.wait(tid, 10)
    assert status.state == TIMEOUT
    assert time.time() - start < 10


def test_cancel_running_task():
    tm = TaskManager()
    tid = tm.submit("cancelme", ["sleep 20 & wait"], timeout=60)
    time.sleep(0.5)
    assert tm.cancel(tid) is True
    status = tm.wait(tid, 10)
    assert status.state == CANCELLED


def test_cancel_unknown_task_returns_false():
    tm = TaskManager()
    assert tm.cancel("nope") is False


def test_list_all_and_status():
    tm = TaskManager()
    a = tm.submit("a", ["true"])
    b = tm.submit("b", ["true"])
    tm.wait(a, 5)
    tm.wait(b, 5)
    ids = {t.task_id for t in tm.list_all()}
    assert {a, b}.issubset(ids)
    assert tm.status(a) is not None


def test_singleton_is_stable():
    assert get_task_manager() is get_task_manager()
