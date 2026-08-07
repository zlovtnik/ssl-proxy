from __future__ import annotations

import os
import subprocess
import sys
import threading
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


def _read_stream(stream: subprocess.PIPE, dest: list[str], dest_lock: threading.Lock, output_stream):
    """Read lines from *stream*, append them (with newline) to *dest* under *dest_lock*,
    and write each line to *output_stream* for real-time output."""
    try:
        for line in iter(stream.readline, ""):
            with dest_lock:
                dest.append(line)
            output_stream.write(line)
            output_stream.flush()
    finally:
        stream.close()


def run(
    cmd: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    stream: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    if capture and stream:
        raise ValueError("capture and stream are mutually exclusive")
    command = tuple(str(part) for part in cmd)
    actual_cwd = cwd or repo_root()
    merged_env = {**os.environ, **dict(env)} if env is not None else None

    if stream:
        proc = subprocess.Popen(
            command,
            cwd=actual_cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=merged_env,
        )
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        lock = threading.Lock()
        t_out = threading.Thread(
            target=_read_stream, args=(proc.stdout, stdout_lines, lock, sys.stdout), daemon=True
        )
        t_err = threading.Thread(
            target=_read_stream, args=(proc.stderr, stderr_lines, lock, sys.stderr), daemon=True
        )
        t_out.start()
        t_err.start()
        t_out.join()
        t_err.join()
        proc.wait()

        stdout_str = "".join(stdout_lines)
        stderr_str = "".join(stderr_lines)
        completed = subprocess.CompletedProcess(
            args=command,
            returncode=proc.returncode,
            stdout=stdout_str,
            stderr=stderr_str,
        )
    else:
        completed = subprocess.run(
            command,
            cwd=actual_cwd,
            check=False,
            capture_output=capture,
            text=True,
            env=merged_env,
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
    stream: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = ["kubectl", "--context", context, *args] if context else ["kubectl", *args]
    return run(
        command,
        cwd=cwd,
        check=check,
        capture=capture,
        stream=stream,
        env=env,
        input_text=input_text,
    )


def helm(
    *args: str,
    context: str,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    stream: bool = False,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = ["helm", "--kube-context", context, *args] if context else ["helm", *args]
    return run(
        command,
        cwd=cwd,
        check=check,
        capture=capture,
        stream=stream,
        env=env,
        input_text=input_text,
    )


def kustomize_build(
    path: str,
    *,
    context: str | None = None,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl kustomize <path>`` to render manifests."""
    command = ["kubectl"]
    if context:
        command.extend(["--context", context])
    command.extend(["kustomize", path])
    return run(command, check=check, capture=capture and not stream, stream=stream)


def kustomize_apply(
    path: str,
    *,
    context: str | None = None,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl apply -k <path>`` to apply kustomize overlays."""
    command = ["kubectl"]
    if context:
        command.extend(["--context", context])
    command.extend(["apply", "-k", path])
    return run(command, check=check, capture=capture and not stream, stream=stream)
