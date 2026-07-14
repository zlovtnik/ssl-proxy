from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from sslproxy_ops.paths import repo_root


@dataclass(slots=True)
class ShellCommandError(RuntimeError):
    command: tuple[str, ...]
    cwd: Path
    returncode: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        rendered = " ".join(self.command)
        detail = self.stderr.strip() or self.stdout.strip()
        suffix = f": {detail}" if detail else ""
        return f"command failed rc={self.returncode} cwd={self.cwd}: {rendered}{suffix}"


def run(
    cmd: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = tuple(str(part) for part in cmd)
    actual_cwd = cwd or repo_root()
    completed = subprocess.run(
        command,
        cwd=actual_cwd,
        check=False,
        capture_output=capture,
        text=True,
        env={**os.environ, **dict(env)} if env is not None else None,
        input=input_text,
    )
    if check and completed.returncode != 0:
        raise ShellCommandError(
            command=command,
            cwd=actual_cwd,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
    return completed


def compose(
    *args: str,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["docker", "compose", *args],
        cwd=cwd,
        check=check,
        capture=capture,
        env=env,
        input_text=input_text,
    )


def kubectl(
    *args: str,
    context: str,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = (
        ["kubectl", "--context", context, *args] if context else ["microk8s", "kubectl", *args]
    )
    return run(
        command,
        cwd=cwd,
        check=check,
        capture=capture,
        env=env,
        input_text=input_text,
    )


def helm(
    *args: str,
    context: str,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = (
        ["helm", "--kube-context", context, *args] if context else ["microk8s", "helm3", *args]
    )
    return run(
        command,
        cwd=cwd,
        check=check,
        capture=capture,
        env=env,
        input_text=input_text,
    )
