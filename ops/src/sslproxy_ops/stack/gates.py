"""Readiness gate checking via kubectl wait."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .shell import kubectl

if TYPE_CHECKING:
    from .core import Gate

DEFAULT_GATE_TIMEOUT = "10m"


def parse_timeout_seconds(timeout: str) -> str:
    """Convert Helm-style timeout (e.g. '15m', '300s', '1h30m') to seconds string."""
    total = 0
    for match in re.finditer(r"(\d+)\s*(s|m|h)", timeout):
        value = int(match.group(1))
        unit = match.group(2)
        if unit == "h":
            total += value * 3600
        elif unit == "m":
            total += value * 60
        else:
            total += value
    if total == 0:
        total = 600
    return f"{total}s"


def _discover_resource(
    gate: Gate,
    release: str,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> str | None:
    """Discover a resource by label selector from gate.discover."""
    assert gate.discover is not None
    kind = gate.discover["kind"]
    selector = gate.discover.get("selector") or f"app.kubernetes.io/name={release}"

    result = kubectl(
        "get",
        kind,
        "-n",
        namespace,
        "-l",
        selector,
        "-o",
        "name",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode != 0:
        return None
    names = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if not names:
        return None
    if len(names) != 1:
        raise RuntimeError(
            f"Gate for release {release!r} selector {selector!r} matched "
            f"{len(names)} {kind} resources; expected exactly one"
        )
    return names[0]


def _resolve_gate_resource(
    gate: Gate,
    release: str,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> str | None:
    """Resolve the full kubectl resource reference from a gate."""
    if gate.resource:
        return gate.resource
    if gate.discover:
        return _discover_resource(gate, release, namespace, context, kubeconfig)
    return None


def _wait_condition(gate: Gate, resource: str | None = None) -> str:
    """Determine the --for condition based on gate type and condition field."""
    if gate.condition == "complete":
        return "condition=complete"
    target = resource or gate.resource or ""
    if target.startswith(("statefulset/", "statefulsets.apps/")):
        return "jsonpath={.status.readyReplicas}={.status.replicas}"
    if target.startswith(("daemonset/", "daemonsets.apps/")):
        return "jsonpath={.status.numberReady}={.status.desiredNumberScheduled}"
    return "condition=Available"


def wait_for_gate(
    gate: Gate,
    release: str,
    namespace: str,
    timeout: str | None = None,
    context: str | None = None,
    kubeconfig: str | None = None,
) -> None:
    """Wait for a single readiness gate to be satisfied.

    Raises ShellError if kubectl wait exits non-zero (timeout or not found).
    """
    resource = _resolve_gate_resource(gate, release, namespace, context, kubeconfig)
    if resource is None:
        raise RuntimeError(
            f"Gate for release {release!r}: could not discover resource "
            f"(discover={gate.discover})"
        )

    timeout_seconds = parse_timeout_seconds(timeout or DEFAULT_GATE_TIMEOUT)
    condition = _wait_condition(gate, resource)

    kubectl(
        "wait",
        resource,
        "-n",
        namespace,
        f"--for={condition}",
        f"--timeout={timeout_seconds}",
        context=context,
        kubeconfig=kubeconfig,
    )


def wait_for_gates(
    gates: list[Gate],
    release: str,
    namespace: str,
    timeout: str | None = None,
    context: str | None = None,
    kubeconfig: str | None = None,
) -> None:
    """Wait for all gates to be satisfied, sequentially."""
    for gate in gates:
        wait_for_gate(
            gate,
            release,
            namespace,
            timeout=timeout,
            context=context,
            kubeconfig=kubeconfig,
        )
