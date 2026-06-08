"""PTY-backed terminal sessions for the web dashboard.

Tools such as nmap or volatility buffer their output when stdout is not a TTY,
which would make a SocketIO terminal appear frozen until the process exits.
To stream line-by-line in real time we allocate a pseudo-terminal (PTY) and
read from the master side, emitting chunks as they arrive.

The runner is cooperative with gevent: it uses ``select`` with a short timeout
and yields via the injected ``sleep`` callable so the SocketIO server stays
responsive. On non-POSIX hosts (no ``pty`` module) it falls back to a pipe.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

try:  # POSIX only
    import fcntl
    import pty
    import select
    import struct
    import termios

    _PTY_AVAILABLE = True
except ImportError:  # pragma: no cover - non-POSIX fallback
    _PTY_AVAILABLE = False


@dataclass
class TerminalSession:
    """Tracks a running PTY-backed process for one browser terminal."""

    sid: str
    argv: list[str]
    cwd: str | None = None
    pid: int | None = None
    fd: int | None = None
    proc: subprocess.Popen | None = None
    exited: bool = False
    exit_code: int | None = None
    _buffer: list[str] = field(default_factory=list)

    def set_winsize(self, rows: int, cols: int) -> None:
        if not (_PTY_AVAILABLE and self.fd is not None):
            return
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except OSError:
            pass

    def write(self, data: str) -> None:
        """Send user keystrokes into the process."""
        if _PTY_AVAILABLE and self.fd is not None and not self.exited:
            try:
                os.write(self.fd, data.encode("utf-8", errors="ignore"))
            except OSError:
                pass
        elif self.proc and self.proc.stdin and not self.exited:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (OSError, ValueError):
                pass

    def terminate(self) -> None:
        if self.exited:
            return
        try:
            if self.pid:
                os.kill(self.pid, signal.SIGTERM)
            elif self.proc:
                self.proc.terminate()
        except (OSError, ProcessLookupError):
            pass


class TerminalManager:
    """Spawns and pumps PTY sessions, emitting output via a callback."""

    def __init__(self) -> None:
        self._sessions: dict[str, TerminalSession] = {}

    def get(self, sid: str) -> TerminalSession | None:
        return self._sessions.get(sid)

    def start(
        self,
        sid: str,
        argv: list[str],
        *,
        shell: bool = False,
        cwd: str | None = None,
        interactive: bool = False,
        initial_command: str | None = None,
    ) -> TerminalSession:
        """Spawn a process attached to a PTY (or a pipe fallback).

        When ``interactive`` is True, an interactive ``bash`` login shell is
        started so the user can type and run commands in the browser terminal.
        If ``initial_command`` is given, it is fed into that shell as the first
        line (e.g. the tool the user clicked "Run" on), after which the prompt
        remains live for further input.
        """
        self.stop(sid)  # ensure one session per sid
        session = TerminalSession(sid=sid, argv=argv, cwd=cwd)

        command = argv[0] if shell else argv
        if _PTY_AVAILABLE:
            pid, fd = pty.fork()
            if pid == 0:  # child
                try:
                    if cwd:
                        os.chdir(cwd)
                    # A sane TERM makes interactive tools (less, msfconsole) behave.
                    os.environ.setdefault("TERM", "xterm-256color")
                    if interactive:
                        os.execvp("/bin/bash", ["/bin/bash", "-i"])
                    elif shell:
                        os.execvp("/bin/bash", ["/bin/bash", "-lc", command])
                    else:
                        os.execvp(argv[0], argv)
                except Exception:  # pragma: no cover - child error path
                    os._exit(127)
            else:  # parent
                session.pid = pid
                session.fd = fd
                if interactive and initial_command:
                    # Feed the tool command into the live shell, then keep the
                    # prompt so the user can keep typing.
                    try:
                        os.write(fd, (initial_command + "\n").encode("utf-8"))
                    except OSError:
                        pass
        else:  # pragma: no cover - non-POSIX
            session.proc = subprocess.Popen(
                "/bin/bash" if interactive else command,
                shell=not interactive and shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                text=True,
                bufsize=1,
            )
            if interactive and initial_command and session.proc and session.proc.stdin:
                try:
                    session.proc.stdin.write(initial_command + "\n")
                    session.proc.stdin.flush()
                except (OSError, ValueError):
                    pass
        self._sessions[sid] = session
        return session

    def pump(
        self,
        sid: str,
        on_output: Callable[[str], None],
        on_exit: Callable[[int], None],
        sleep: Callable[[float], None],
    ) -> None:
        """Read output until the process exits, emitting chunks as they arrive.

        ``sleep`` is the cooperative yield (e.g. ``socketio.sleep``) so this can
        run inside a gevent background task without blocking other clients.
        """
        session = self._sessions.get(sid)
        if session is None:
            return

        if _PTY_AVAILABLE and session.fd is not None:
            self._pump_pty(session, on_output, on_exit, sleep)
        elif session.proc is not None:  # pragma: no cover - fallback
            self._pump_pipe(session, on_output, on_exit, sleep)

    def _pump_pty(self, session, on_output, on_exit, sleep) -> None:
        fd = session.fd
        assert fd is not None
        while True:
            try:
                ready, _, _ = select.select([fd], [], [], 0.1)
            except (OSError, ValueError):
                break
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                on_output(data.decode("utf-8", errors="replace"))
            else:
                # No data ready; check whether the child has exited.
                pid, status = os.waitpid(session.pid, os.WNOHANG)
                if pid != 0:
                    session.exited = True
                    session.exit_code = os.waitstatus_to_exitcode(status)
                    break
            sleep(0)
        self._finalise(session, on_exit)

    def _pump_pipe(self, session, on_output, on_exit, sleep) -> None:  # pragma: no cover
        proc = session.proc
        assert proc is not None and proc.stdout is not None
        for line in proc.stdout:
            on_output(line)
            sleep(0)
        proc.wait()
        session.exited = True
        session.exit_code = proc.returncode
        self._finalise(session, on_exit)

    def _finalise(self, session: TerminalSession, on_exit: Callable[[int], None]) -> None:
        if not session.exited:
            try:
                _, status = os.waitpid(session.pid, 0) if session.pid else (0, 0)
                session.exit_code = os.waitstatus_to_exitcode(status) if session.pid else 0
            except (OSError, ChildProcessError):
                session.exit_code = session.exit_code or 0
            session.exited = True
        if session.fd is not None:
            try:
                os.close(session.fd)
            except OSError:
                pass
        on_exit(session.exit_code if session.exit_code is not None else 0)
        self._sessions.pop(session.sid, None)

    def stop(self, sid: str) -> None:
        session = self._sessions.get(sid)
        if session is None:
            return
        session.terminate()
        if session.fd is not None:
            try:
                os.close(session.fd)
            except OSError:
                pass
        self._sessions.pop(sid, None)
