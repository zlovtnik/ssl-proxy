"""Subprocess wrappers for kubectl and helm with context propagation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


class ShellError(RuntimeError):
    """Raised when a subprocess exits non-zero."""

    def __init__(
        self,
        command: tuple[str, ...],
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        detail = stderr.strip() or stdout.strip()
        suffix = f": {detail}" if detail else ""
        super().__init__(f"command failed rc={returncode}: {' '.join(command)}{suffix}")


def _run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command. Raises ShellError on non-zero exit when check=True."""
    if stream:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        import sys

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        assert proc.stdout is not None
        assert proc.stderr is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            stdout_lines.append(line)
        for line in proc.stderr:
            sys.stderr.write(line)
            sys.stderr.flush()
            stderr_lines.append(line)
        proc.wait()
        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
        )
    else:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=capture,
            text=True,
            input=input_text,
        )
    if check and result.returncode != 0:
        raise ShellError(
            command=tuple(cmd),
            returncode=result.returncode,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
        )
    return result


def kubectl(
    *args: str,
    context: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    capture: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run kubectl with optional context/kubeconfig propagation."""
    cmd = ["kubectl"]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    elif context:
        cmd.extend(["--context", context])
    cmd.extend(args)
    return _run(cmd, check=check, capture=capture, input_text=input_text)


def helm(
    *args: str,
    context: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run helm with optional context/kubeconfig propagation."""
    cmd = ["helm"]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    elif context:
        cmd.extend(["--kube-context", context])
    cmd.extend(args)
    return _run(cmd, check=check, capture=capture, stream=stream, input_text=input_text)
