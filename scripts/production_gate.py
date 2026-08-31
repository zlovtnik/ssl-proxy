#!/usr/bin/env python3
"""Wait for the three production Argo CD Applications at an exact Git SHA."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from image_contract import ImageContractError, load_image_contracts


APPLICATIONS = (
    "ssl-proxy-prod-bootstrap",
    "ssl-proxy-prod-data-plane",
    "ssl-proxy-prod-app-stack",
)
DEFAULT_NAMESPACE = "argocd"
PRODUCTION_NAMESPACE = "prod-ssl-proxy"
EXPECTED_KUBERNETES_API = "https://192.168.1.242:6443"
EXPECTED_NODE = "wiretrap"
EXPECTED_NODE_IP = "192.168.1.242"
EXPECTED_REPOSITORY = "https://github.com/zlovtnik/ssl-proxy.git"
EXPECTED_APPLICATION_PATHS = {
    "ssl-proxy-prod-bootstrap": "cyber-stack/matrix/prod/bootstrap",
    "ssl-proxy-prod-data-plane": "cyber-stack/matrix/prod/data-plane",
    "ssl-proxy-prod-app-stack": "cyber-stack/matrix/prod/app-stack",
}
DEFAULT_TIMEOUT = "30m"
DEFAULT_POLL_INTERVAL_SECONDS = 10.0
KUBECTL_REQUEST_TIMEOUT = "10s"
RBAC_MAX_WORKERS = 8
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


@dataclass(frozen=True)
class AccessReview:
    verb: str
    resource: str
    namespace: str | None
    expected: bool
    failure: str


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
    repo_url: str = ""
    target_revision: str = ""
    path: str = ""
    destination_server: str = ""
    destination_namespace: str = ""
    images: tuple[str, ...] = ()

    def ready_for(
        self,
        revision: str,
        expected_images: frozenset[str],
        verify_contract: bool = False,
    ) -> bool:
        contract_valid = not verify_contract or (
            self.repo_url == EXPECTED_REPOSITORY
            and self.target_revision == "main"
            and self.path == EXPECTED_APPLICATION_PATHS[self.name]
            and self.destination_server == "https://kubernetes.default.svc"
            and self.destination_namespace == PRODUCTION_NAMESPACE
            and expected_images.issubset(self.images)
        )
        return (
            not self.query_error
            and self.revision == revision
            and self.sync == "Synced"
            and self.health == "Healthy"
            and contract_valid
        )

    def diagnostic(self) -> str:
        if self.query_error:
            return f"{self.name}: {self.query_error}"
        detail = (
            f"{self.name}: revision={self.revision} sync={self.sync} "
            f"health={self.health} operation={self.operation_phase}"
        )
        if self.path:
            detail += f" path={self.path}"
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
        expected_images: Mapping[str, frozenset[str]] | None = None,
        on_line: Callable[[str], None] | None = None,
        verify_wiretrap: bool = False,
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
        self.expected_images = expected_images or {}
        self.on_line = on_line
        self.verify_wiretrap = verify_wiretrap
        self.lines: list[str] = []

    def _append(self, *lines: str) -> None:
        self.lines.extend(lines)
        if self.on_line is not None:
            for line in lines:
                self.on_line(line)

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
        arguments.append(f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}")
        result = self._kubectl(*arguments)
        answer = result.stdout.strip().lower()
        if answer == "yes":
            return True, ""
        if answer == "no":
            return False, ""
        detail = sanitize_diagnostic(result.stderr or result.stdout or f"exit {result.returncode}")
        return None, detail

    def _access_reviews(self) -> tuple[AccessReview, ...]:
        reviews = []
        for name in APPLICATIONS:
            reviews.append(
                AccessReview(
                    verb="get",
                    resource=f"applications.argoproj.io/{name}",
                    namespace=self.namespace,
                    expected=True,
                    failure=f"cannot get {name}",
                )
            )
        if self.verify_wiretrap:
            reviews.append(
                AccessReview(
                    verb="get",
                    resource=f"nodes/{EXPECTED_NODE}",
                    namespace=None,
                    expected=True,
                    failure=f"cannot get node {EXPECTED_NODE}",
                )
            )

        scopes = (
            ("all namespaces", None),
            (f"namespace {self.namespace}", self.namespace),
            (f"namespace {PRODUCTION_NAMESPACE}", PRODUCTION_NAMESPACE),
        )
        for scope_label, scope_namespace in scopes:
            for verb in SECRET_READ_VERBS:
                reviews.append(
                    AccessReview(
                        verb=verb,
                        resource="secrets",
                        namespace=scope_namespace,
                        expected=False,
                        failure=f"Secret {verb} isolation failed in {scope_label}",
                    )
                )

            for verb in MUTATION_VERBS:
                for resource in MUTATION_RESOURCES:
                    reviews.append(
                        AccessReview(
                            verb=verb,
                            resource=resource,
                            namespace=scope_namespace,
                            expected=False,
                            failure=(
                                f"mutation isolation failed in {scope_label} for "
                                f"{verb} {resource}"
                            ),
                        )
                    )
        return tuple(reviews)

    def _run_access_review(self, review: AccessReview) -> str | None:
        allowed, detail = self._can_i(
            review.verb, review.resource, namespace=review.namespace
        )
        if allowed is review.expected:
            return None
        default = "denied" if review.expected else "unexpectedly allowed"
        return f"  {review.failure}: {detail or default}"

    def _verify_access(self) -> bool:
        self._append("RBAC preflight:")
        reviews = self._access_reviews()
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=RBAC_MAX_WORKERS
        ) as executor:
            failures = tuple(executor.map(self._run_access_review, reviews))
        self._append(*(failure for failure in failures if failure is not None))
        valid = not any(failure is not None for failure in failures)
        if valid:
            self._append(
                "  PASS: three named Application reads allowed; Secret reads and "
                "representative mutations denied cluster-wide and in the Argo CD "
                "and production namespaces"
            )
        return valid

    def _verify_wiretrap(self) -> bool:
        server = self._kubectl(
            "config", "view", "--minify", "-o",
            "jsonpath={.clusters[0].cluster.server}",
        )
        if server.returncode != 0 or server.stdout.strip() != EXPECTED_KUBERNETES_API:
            self._append(
                "Wiretrap preflight failed: Kubernetes API is "
                + sanitize_diagnostic(server.stdout or server.stderr or "UNKNOWN")
            )
            return False
        node = self._kubectl(
            "get", "nodes", EXPECTED_NODE, "-o", "json",
            f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}",
        )
        if node.returncode != 0:
            self._append(
                "Wiretrap preflight failed: node query failed: "
                + sanitize_diagnostic(node.stderr or node.stdout)
            )
            return False
        try:
            document = json.loads(node.stdout)
        except json.JSONDecodeError as error:
            self._append(f"Wiretrap preflight failed: invalid node JSON: {error}")
            return False
        addresses = {
            str(item.get("address"))
            for item in _list(_mapping(_mapping(document).get("status")).get("addresses"))
            if _mapping(item).get("type") == "InternalIP"
        }
        ready = any(
            _mapping(condition).get("type") == "Ready"
            and _mapping(condition).get("status") == "True"
            for condition in _list(_mapping(_mapping(document).get("status")).get("conditions"))
        )
        if EXPECTED_NODE_IP not in addresses or not ready:
            self._append(
                f"Wiretrap preflight failed: node={EXPECTED_NODE} "
                f"internalIPs={sorted(addresses)} ready={ready}"
            )
            return False
        self._append(
            f"Wiretrap preflight: API={EXPECTED_KUBERNETES_API} "
            f"node={EXPECTED_NODE} InternalIP={EXPECTED_NODE_IP} Ready=True"
        )
        return True

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
        spec = _mapping(document.get("spec"))
        source = _mapping(spec.get("source"))
        destination = _mapping(spec.get("destination"))
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
            repo_url=str(source.get("repoURL", "")),
            target_revision=str(source.get("targetRevision", "")),
            path=str(source.get("path", "")),
            destination_server=str(destination.get("server", "")),
            destination_namespace=str(destination.get("namespace", "")),
            images=tuple(str(image) for image in _list(_mapping(status.get("summary")).get("images"))),
        )

    def run(self) -> tuple[int, str]:
        self._append(
            (
                "PRODUCTION REVISION GATE (READ ONLY)",
                f"Expected revision: {self.revision}",
                f"Argo namespace:   {self.namespace}",
                f"Timeout seconds:  {self.timeout_seconds:g}",
                "Mutation policy:   Kubernetes and Argo CD reads only",
            )
        )
        if self.verify_rbac and not self._verify_access():
            self._append("RESULT: FAILED (RBAC preflight)")
            return 1, "\n".join(self.lines) + "\n"
        if self.verify_wiretrap and not self._verify_wiretrap():
            self._append("RESULT: FAILED (Wiretrap preflight)")
            return 1, "\n".join(self.lines) + "\n"

        deadline = self.clock() + self.timeout_seconds
        previous_snapshot: tuple[ApplicationState, ...] | None = None
        attempt = 0
        while True:
            attempt += 1
            attempt_started = self.clock()
            states = tuple(self._query_application(name) for name in APPLICATIONS)
            if states != previous_snapshot:
                self._append(f"Attempt {attempt}:")
                self._append(*(f"  {state.diagnostic()}" for state in states))
                previous_snapshot = states
            terminal = next(
                (
                    state
                    for state in states
                    if state.revision == self.revision
                    and state.operation_phase in {"Error", "Failed"}
                ),
                None,
            )
            if terminal is not None:
                self._append(f"RESULT: FAILED (terminal Argo operation: {terminal.diagnostic()})")
                return 1, "\n".join(self.lines) + "\n"
            if all(
                state.ready_for(
                    self.revision,
                    self.expected_images.get(state.name, frozenset()),
                    state.name in self.expected_images,
                )
                for state in states
            ):
                self._append(
                    f"RESULT: PASSED (all Applications Synced/Healthy at {self.revision})"
                )
                return 0, "\n".join(self.lines) + "\n"
            remaining = deadline - self.clock()
            if remaining <= 0:
                self._append(
                    f"RESULT: FAILED (timed out waiting for exact revision {self.revision})"
                )
                return 1, "\n".join(self.lines) + "\n"
            query_seconds = self.clock() - attempt_started
            delay = max(0.0, self.poll_interval_seconds - query_seconds)
            self.sleeper(min(delay, remaining))


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
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        expected_images = {
            "ssl-proxy-prod-bootstrap": frozenset(),
            "ssl-proxy-prod-data-plane": frozenset(
                contract.reference
                for contract in load_image_contracts(arguments.repository_root, "prod")
                if contract.slice_name == "data-plane"
            ),
            "ssl-proxy-prod-app-stack": frozenset(
                contract.reference
                for contract in load_image_contracts(arguments.repository_root, "prod")
                if contract.slice_name == "app-stack"
            ),
        }
        gate = ProductionGate(
            arguments.revision,
            kubectl=arguments.kubectl,
            kube_context=arguments.kube_context,
            namespace=arguments.namespace,
            timeout_seconds=arguments.timeout,
            poll_interval_seconds=arguments.poll_interval,
            expected_images=expected_images,
            on_line=lambda line: print(line, flush=True),
            verify_wiretrap=True,
        )
    except (ValueError, ImageContractError) as error:
        print(f"production-gate: {error}", file=sys.stderr)
        return 2
    returncode, _report = gate.run()
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
