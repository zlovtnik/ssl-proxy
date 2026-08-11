#!/usr/bin/env python3
"""Wait for the three production Argo CD Applications at an exact Git SHA."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


APPLICATIONS = (
    "ssl-proxy-prod-bootstrap",
    "ssl-proxy-prod-data-plane",
    "ssl-proxy-prod-app-stack",
)
DEFAULT_NAMESPACE = "argocd"
PRODUCTION_NAMESPACE = "prod-ssl-proxy"
DEFAULT_TIMEOUT = "30m"
DEFAULT_POLL_INTERVAL_SECONDS = 10.0
SECRET_READ_VERBS = ("get", "list", "watch")
MUTATION_VERBS = ("create", "update", "patch", "delete")
MUTATION_RESOURCES = (
    "applications.argoproj.io",
    "secrets",
    "deployments.apps",
    "roles.rbac.authorization.k8s.io",
    "rolebindings.rbac.authorization.k8s.io",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[Sequence[str]], CommandResult]


def subprocess_runner(command: Sequence[str]) -> CommandResult:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return CommandResult(result.returncode, result.stdout, result.stderr)


def parse_duration(value: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smh]?)", value.strip())
    if match is None:
        raise argparse.ArgumentTypeError("duration must be a number followed by s, m, or h")
    multiplier = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]
    return float(match.group(1)) * multiplier


def sanitize_diagnostic(value: Any, limit: int = 300) -> str:
    text = str(value or "")
    text = re.sub(
        r"(?is)-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----.*?"
        r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        text,
    )
    text = re.sub(
        r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+:[^/@\s]+@",
        r"\1[REDACTED]@",
        text,
    )
    text = re.sub(
        r'''(?i)(["']?authorization["']?)(\s*[=:]\s*)'''
        r'''(?:"[^"]*"|'[^']*'|(?:(?:basic|bearer)\s+)?[^\s,;&]+)''',
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)\b[^\s:@/]+:[^\s@/]+@(?=tcp\(|[a-z0-9.-]+(?::\d+)?)",
        "[REDACTED]@",
        text,
    )
    sensitive_name = (
        r"[a-z0-9_.-]*(?:password|passwd|token|secret|api[-_]?key|"
        r"authorization|"
        r"access[-_]?key|private[-_]?key|preshared[-_]?key|encrypt[-_]?key|"
        r"jwt[-_]?secret|htpasswd|dsn)[a-z0-9_.-]*"
    )
    text = re.sub(
        rf'''(?i)(?<![a-z0-9_.-])(["']?{sensitive_name}["']?)(\s*[=:]\s*)'''
        r'(?:"[^"]*"|\'[^\']*\'|[^\s,;&]+)',
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(
        rf"(?i)(--?{sensitive_name})(\s+)([^\s,;&]+)",
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "[REDACTED JWT]",
        text,
    )
    return " ".join(text.split())[:limit]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


@dataclass(frozen=True)
class ApplicationState:
    name: str
    revision: str = "UNKNOWN"
    sync: str = "Unknown"
    health: str = "Unknown"
    operation_phase: str = "Unknown"
    messages: tuple[str, ...] = ()
    query_error: str = ""

    def ready_for(self, revision: str) -> bool:
        return (
            not self.query_error
            and self.revision == revision
            and self.sync == "Synced"
            and self.health == "Healthy"
        )

    def diagnostic(self) -> str:
        if self.query_error:
            return f"{self.name}: {self.query_error}"
        detail = (
            f"{self.name}: revision={self.revision} sync={self.sync} "
            f"health={self.health} operation={self.operation_phase}"
        )
        if self.messages:
            detail += " messages=" + " | ".join(self.messages)
        return detail


class ProductionGate:
    def __init__(
        self,
        revision: str,
        *,
        kubectl: str = "kubectl",
        kube_context: str = "",
        namespace: str = DEFAULT_NAMESPACE,
        timeout_seconds: float = 30 * 60,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        verify_rbac: bool = True,
        runner: CommandRunner = subprocess_runner,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is None:
            raise ValueError("revision must be a full lowercase Git SHA")
        if timeout_seconds < 0 or poll_interval_seconds <= 0:
            raise ValueError("timeout must be non-negative and poll interval must be positive")
        self.revision = revision
        self.kubectl = kubectl
        self.kube_context = kube_context.strip()
        self.namespace = namespace
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.verify_rbac = verify_rbac
        self.runner = runner
        self.clock = clock
        self.sleeper = sleeper
        self.lines: list[str] = []

    def _kubectl(self, *arguments: str) -> CommandResult:
        command = [self.kubectl]
        if self.kube_context:
            command.extend(("--context", self.kube_context))
        command.extend(arguments)
        return self.runner(command)

    def _can_i(
        self, verb: str, resource: str, *, namespace: str | None
    ) -> tuple[bool | None, str]:
        arguments = ["auth", "can-i", verb, resource]
        if namespace is None:
            arguments.append("--all-namespaces")
        else:
            arguments.extend(("--namespace", namespace))
        result = self._kubectl(*arguments)
        answer = result.stdout.strip().lower()
        if answer == "yes":
            return True, ""
        if answer == "no":
            return False, ""
        detail = sanitize_diagnostic(result.stderr or result.stdout or f"exit {result.returncode}")
        return None, detail

    def _verify_access(self) -> bool:
        self.lines.append("RBAC preflight:")
        valid = True
        for name in APPLICATIONS:
            allowed, detail = self._can_i(
                "get", f"applications.argoproj.io/{name}", namespace=self.namespace
            )
            if allowed is True:
                continue
            valid = False
            suffix = detail or "denied"
            self.lines.append(f"  cannot get {name}: {suffix}")

        scopes = (
            ("all namespaces", None),
            (f"namespace {self.namespace}", self.namespace),
            (f"namespace {PRODUCTION_NAMESPACE}", PRODUCTION_NAMESPACE),
        )
        for scope_label, scope_namespace in scopes:
            for verb in SECRET_READ_VERBS:
                secret_read, detail = self._can_i(
                    verb, "secrets", namespace=scope_namespace
                )
                if secret_read is not False:
                    valid = False
                    suffix = detail or "unexpectedly allowed"
                    self.lines.append(
                        f"  Secret {verb} isolation failed in {scope_label}: {suffix}"
                    )

            for verb in MUTATION_VERBS:
                for resource in MUTATION_RESOURCES:
                    allowed, detail = self._can_i(
                        verb, resource, namespace=scope_namespace
                    )
                    if allowed is False:
                        continue
                    valid = False
                    suffix = detail or "unexpectedly allowed"
                    self.lines.append(
                        f"  mutation isolation failed in {scope_label} for "
                        f"{verb} {resource}: {suffix}"
                    )
        if valid:
            self.lines.append(
                "  PASS: three named Application reads allowed; Secret reads and "
                "representative mutations denied cluster-wide and in the Argo CD "
                "and production namespaces"
            )
        return valid

    def _query_application(self, name: str) -> ApplicationState:
        result = self._kubectl(
            "--namespace",
            self.namespace,
            "get",
            "applications.argoproj.io",
            name,
            "-o",
            "json",
            "--request-timeout=10s",
        )
        if result.returncode != 0:
            detail = sanitize_diagnostic(result.stderr or result.stdout or f"exit {result.returncode}")
            if "notfound" in detail.replace(" ", "").lower() or "not found" in detail.lower():
                return ApplicationState(name=name, query_error="MISSING")
            return ApplicationState(name=name, query_error=f"query failed: {detail}")
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            return ApplicationState(name=name, query_error=f"invalid JSON: {error}")
        if not isinstance(document, Mapping):
            return ApplicationState(name=name, query_error="invalid response object")
        status = _mapping(document.get("status"))
        sync = _mapping(status.get("sync"))
        health = _mapping(status.get("health"))
        operation = _mapping(status.get("operationState"))
        messages = []
        operation_message = sanitize_diagnostic(operation.get("message"))
        if operation_message:
            messages.append(operation_message)
        for condition in _list(status.get("conditions")):
            condition = _mapping(condition)
            message = sanitize_diagnostic(condition.get("message"))
            condition_type = sanitize_diagnostic(condition.get("type"), limit=80)
            if message:
                messages.append(f"{condition_type}: {message}" if condition_type else message)
        return ApplicationState(
            name=name,
            revision=str(sync.get("revision", "UNKNOWN")),
            sync=str(sync.get("status", "Unknown")),
            health=str(health.get("status", "Unknown")),
            operation_phase=str(operation.get("phase", "Unknown")),
            messages=tuple(messages),
        )

    def run(self) -> tuple[int, str]:
        self.lines.extend(
            (
                "PRODUCTION REVISION GATE (READ ONLY)",
                f"Expected revision: {self.revision}",
                f"Argo namespace:   {self.namespace}",
                f"Timeout seconds:  {self.timeout_seconds:g}",
                "Mutation policy:   Kubernetes and Argo CD reads only",
            )
        )
        if self.verify_rbac and not self._verify_access():
            self.lines.append("RESULT: FAILED (RBAC preflight)")
            return 1, "\n".join(self.lines) + "\n"

        deadline = self.clock() + self.timeout_seconds
        previous_snapshot: tuple[ApplicationState, ...] | None = None
        attempt = 0
        while True:
            attempt += 1
            states = tuple(self._query_application(name) for name in APPLICATIONS)
            if states != previous_snapshot:
                self.lines.append(f"Attempt {attempt}:")
                self.lines.extend(f"  {state.diagnostic()}" for state in states)
                previous_snapshot = states
            if all(state.ready_for(self.revision) for state in states):
                self.lines.append(
                    f"RESULT: PASSED (all Applications Synced/Healthy at {self.revision})"
                )
                return 0, "\n".join(self.lines) + "\n"
            remaining = deadline - self.clock()
            if remaining <= 0:
                self.lines.append(
                    f"RESULT: FAILED (timed out waiting for exact revision {self.revision})"
                )
                return 1, "\n".join(self.lines) + "\n"
            self.sleeper(min(self.poll_interval_seconds, remaining))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kube-context", default="")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--timeout", type=parse_duration, default=parse_duration(DEFAULT_TIMEOUT))
    parser.add_argument(
        "--poll-interval",
        type=parse_duration,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        gate = ProductionGate(
            arguments.revision,
            kubectl=arguments.kubectl,
            kube_context=arguments.kube_context,
            namespace=arguments.namespace,
            timeout_seconds=arguments.timeout,
            poll_interval_seconds=arguments.poll_interval,
        )
    except ValueError as error:
        print(f"production-gate: {error}", file=sys.stderr)
        return 2
    returncode, report = gate.run()
    sys.stdout.write(report)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
