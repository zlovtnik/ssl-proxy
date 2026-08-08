"""Subprocess wrappers for kubectl and Helm."""

from __future__ import annotations

import subprocess
from pathlib import Path

from sslproxy_ops.paths import repo_root


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


def _resolve_kustomize_path(path: str) -> str:
    """Resolve a relative kustomize path against the repo root."""
    p = Path(path)
    if p.is_absolute():
        return str(p)
    return str(repo_root() / p)


def kustomize_build(
    path: str,
    *,
    namespace: str | None = None,
    context: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl kustomize <path>`` to render manifests."""
    cmd = ["kubectl"]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    elif context:
        cmd.extend(["--context", context])
    cmd.extend(["kustomize", _resolve_kustomize_path(path)])
    return _run(cmd, check=check, capture=capture, stream=stream)


def kustomize_apply(
    path: str,
    *,
    namespace: str | None = None,
    dry_run: bool = False,
    wait_for_completion: bool = False,
    label_selector: str | None = None,
    context: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    capture: bool = True,
    stream: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl apply -k <path>`` to apply manifests."""
    cmd = ["kubectl"]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    elif context:
        cmd.extend(["--context", context])
    cmd.extend(["apply", "-k", _resolve_kustomize_path(path)])
    if namespace:
        cmd.extend(["-n", namespace])
    if dry_run:
        cmd.append("--dry-run=server")
    result = _run(cmd, check=check, capture=capture, stream=stream)
    if wait_for_completion and not dry_run and namespace:
        wait_cmd = ["kubectl"]
        if kubeconfig:
            wait_cmd.extend(["--kubeconfig", kubeconfig])
        elif context:
            wait_cmd.extend(["--context", context])
        wait_cmd.extend([
            "wait",
            "--for=condition=Complete",
        ])
        if label_selector:
            wait_cmd.extend(["-l", label_selector])
        else:
            wait_cmd.extend(["--all"])
        wait_cmd.extend([
            "jobs",
            "-n",
            namespace,
            "--timeout=300s",
        ])
        wait_result = _run(wait_cmd, check=False, capture=capture, stream=stream)
        if wait_result.returncode != 0:
            wait_output = (wait_result.stdout or "") + (wait_result.stderr or "")
            if "No matching resources found" in wait_output:
                pass
            else:
                failed_cmd = ["kubectl"]
                if kubeconfig:
                    failed_cmd.extend(["--kubeconfig", kubeconfig])
                elif context:
                    failed_cmd.extend(["--context", context])
                failed_cmd.extend([
                    "wait",
                    "--for=condition=Failed",
                ])
                if label_selector:
                    failed_cmd.extend(["-l", label_selector])
                else:
                    failed_cmd.extend(["--all"])
                failed_cmd.extend([
                    "jobs",
                    "-n",
                    namespace,
                    "--timeout=5s",
                ])
                failed_check = _run(failed_cmd, check=False, capture=capture, stream=stream)
                if failed_check.returncode == 0:
                    if check:
                        raise ShellError(
                            command=("kubectl", "wait"),
                            returncode=1,
                            stdout="",
                            stderr=(failed_check.stdout or "job failed"),
                        )
                    result.returncode = 1
                    result.stdout = (result.stdout or "") + "\n" + (failed_check.stdout or "")
                else:
                    if check:
                        raise ShellError(
                            command=("kubectl", "wait"),
                            returncode=1,
                            stdout="",
                            stderr="timed out waiting for jobs to complete or fail",
                        )
                    result.returncode = 1
                    result.stderr = "timed out waiting for jobs to complete or fail"
    return result


def kustomize_validate(
    path: str,
    *,
    context: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl kustomize <path>`` and check for errors."""
    cmd = ["kubectl"]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    elif context:
        cmd.extend(["--context", context])
    cmd.extend(["kustomize", _resolve_kustomize_path(path)])
    return _run(cmd, check=check, capture=capture)
