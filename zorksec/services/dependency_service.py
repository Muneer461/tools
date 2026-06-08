"""Dependency engine: detect runtimes needed to install/run tools.

Detects Python, Java, Docker, Docker Compose, Go, Cargo, and Git, reporting
presence, version, and a beginner-friendly install hint (Auto / Manual / Skip
is decided by the UI layer).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from zorksec.services.discovery_service import _run, binary_present


@dataclass
class DependencyStatus:
    key: str
    name: str
    present: bool
    version: str | None
    install_hint: str


@dataclass
class _Dep:
    key: str
    name: str
    binary: str
    version_args: list[str]
    install_hint: str
    version_regex: str = r"(\d+\.\d+(?:\.\d+)?)"


_DEPENDENCIES: list[_Dep] = [
    _Dep("python", "Python 3", "python3", ["--version"], "sudo apt install -y python3 python3-pip"),
    _Dep("git", "Git", "git", ["--version"], "sudo apt install -y git"),
    _Dep("docker", "Docker Engine", "docker", ["--version"], "sudo apt install -y docker.io"),
    _Dep("compose", "Docker Compose", "docker", ["compose", "version"],
         "sudo apt install -y docker-compose-plugin"),
    _Dep("go", "Go", "go", ["version"], "sudo apt install -y golang-go"),
    _Dep("cargo", "Rust / Cargo", "cargo", ["--version"],
         "curl https://sh.rustup.rs -sSf | sh"),
    _Dep("java", "Java (JRE/JDK)", "java", ["-version"], "sudo apt install -y default-jdk"),
]


def _extract_version(text: str, regex: str) -> str | None:
    match = re.search(regex, text)
    return match.group(1) if match else None


class DependencyService:
    """Detects the presence and versions of build/runtime dependencies."""

    def detect(self) -> list[DependencyStatus]:
        results: list[DependencyStatus] = []
        for dep in _DEPENDENCIES:
            present = binary_present(dep.binary)
            version: str | None = None
            if present:
                # Some tools (java) print version to stderr; _run captures stdout
                # only, so fall back to combined output for version parsing.
                out = _run([dep.binary, *dep.version_args])
                if not out:
                    out = _combined_output([dep.binary, *dep.version_args])
                version = _extract_version(out, dep.version_regex)
                # Docker Compose 'present' depends on the subcommand working.
                if dep.key == "compose" and not out:
                    present = False
            results.append(
                DependencyStatus(
                    key=dep.key,
                    name=dep.name,
                    present=present,
                    version=version,
                    install_hint=dep.install_hint,
                )
            )
        return results

    def missing(self) -> list[DependencyStatus]:
        return [d for d in self.detect() if not d.present]


def _combined_output(cmd: list[str], timeout: int = 15) -> str:
    """Run a command capturing stdout+stderr (for tools that use stderr)."""
    import subprocess

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return ""
