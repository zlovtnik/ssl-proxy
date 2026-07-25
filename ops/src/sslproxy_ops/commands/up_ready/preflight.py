"""Cluster preflight checks.

Non-mutating verification of Kubernetes prerequisites before deployment.
Checks fail fast in seconds, before Wave 1 begins.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step, warn
from sslproxy_ops.paths import repo_root


@dataclass(slots=True)
class ClusterSpec:
    minimum_ready_nodes: int = 1


@dataclass(slots=True)
class SecretSpec:
    namespace: str
    name: str
    key: str | None = None


@dataclass(slots=True)
class NodeRequirement:
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PreflightSpec:
    cluster: ClusterSpec = field(default_factory=ClusterSpec)
    storage_classes: list[str] = field(default_factory=list)
    secrets: list[SecretSpec] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    node_requirements: dict[str, NodeRequirement] = field(default_factory=dict)
    host_devices: list[str] = field(default_factory=list)
    crds: list[str] = field(default_factory=list)
    min_disk_space_gb: int | None = None
    conflicting_releases: bool = True


def _load_preflight_spec() -> PreflightSpec:
    """Load preflight spec from YAML file."""
    spec_path = repo_root() / "ops" / "src" / "sslproxy_ops" / "commands" / "up_ready" / "preflight_spec.yaml"
    if not spec_path.exists():
        return PreflightSpec()

    with open(spec_path) as f:
        raw = yaml.safe_load(f) or {}

    preflight = raw.get("preflight", {})

    cluster_raw = preflight.get("cluster", {})
    cluster = ClusterSpec(
        minimum_ready_nodes=cluster_raw.get("minimum_ready_nodes", 1)
    )

    storage_classes = preflight.get("storage_classes", [])

    secrets = []
    for s in preflight.get("secrets", []):
        if isinstance(s, str):
            parts = s.split("/", 1)
            if len(parts) == 2:
                secrets.append(SecretSpec(namespace=parts[0], name=parts[1]))
            else:
                secrets.append(SecretSpec(namespace="default", name=s))
        elif isinstance(s, dict):
            secrets.append(SecretSpec(
                namespace=s.get("namespace", "default"),
                name=s["name"],
                key=s.get("key"),
            ))

    service_accounts = preflight.get("service_accounts", [])

    node_requirements = {}
    for name, req in preflight.get("node_requirements", {}).items():
        node_requirements[name] = NodeRequirement(
            labels=req.get("labels", {})
        )

    host_devices = preflight.get("host_devices", [])
    crds = preflight.get("crds", [])
    min_disk_space_gb = preflight.get("min_disk_space_gb")
    conflicting_releases = preflight.get("conflicting_releases", True)

    return PreflightSpec(
        cluster=cluster,
        storage_classes=storage_classes,
        secrets=secrets,
        service_accounts=service_accounts,
        node_requirements=node_requirements,
        host_devices=host_devices,
        crds=crds,
        min_disk_space_gb=min_disk_space_gb,
        conflicting_releases=conflicting_releases,
    )


def check_api_connectivity(ctx: UpReadyContext) -> None:
    """Verify Kubernetes API is reachable."""
    result = shell.kubectl(
        "cluster-info",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise UpReadyError(
            f"Cannot connect to Kubernetes API server: {(result.stderr or '').strip()}"
        )
    step("S01", "kubernetes_api: reachable")


def check_nodes_ready(ctx: UpReadyContext, minimum_ready: int) -> None:
    """Verify Ready nodes and reject DiskPressure."""
    result = shell.kubectl(
        "get", "nodes",
        "-o", "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise UpReadyError(
            f"Failed to query nodes: {(result.stderr or '').strip()}"
        )

    try:
        payload = json.loads(result.stdout or "{}")
        nodes = payload.get("items", [])
        ready_count = 0
        for node in nodes:
            conditions = (node.get("status") or {}).get("conditions", [])
            disk_pressure = next(
                (c for c in conditions if c.get("type") == "DiskPressure"), None
            )
            if disk_pressure and disk_pressure.get("status") != "False":
                node_name = (node.get("metadata") or {}).get("name", "unknown")
                raise UpReadyError(f"Node {node_name} reports DiskPressure")
            for c in conditions:
                if c.get("type") == "Ready" and c.get("status") == "True":
                    ready_count += 1
                    break
    except json.JSONDecodeError:
        raise UpReadyError("Failed to parse node status")

    if ready_count < minimum_ready:
        raise UpReadyError(
            f"Insufficient Ready nodes: {ready_count} found, "
            f"{minimum_ready} required"
        )
    step("S01", f"nodes_ready: {ready_count} node(s) Ready (minimum={minimum_ready})")


def check_node_requirements(
    ctx: UpReadyContext, requirements: dict[str, NodeRequirement]
) -> None:
    """Verify at least one Ready node satisfies each declared label contract."""

    for workload, requirement in requirements.items():
        selector = ",".join(f"{key}={value}" for key, value in requirement.labels.items())
        result = shell.kubectl(
            "get",
            "nodes",
            "-l",
            selector,
            "-o",
            "json",
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            raise UpReadyError(f"Failed to query nodes for {workload}")
        try:
            nodes = json.loads(result.stdout or "{}").get("items", [])
        except json.JSONDecodeError as exc:
            raise UpReadyError(f"Failed to parse nodes for {workload}") from exc
        if not nodes:
            raise UpReadyError(
                f"No node satisfies {workload} labels: {selector or '(none)'}"
            )
    if requirements:
        step("S01", f"node_labels: {len(requirements)} requirement(s) satisfied")


def check_storage_classes(ctx: UpReadyContext, required: list[str]) -> None:
    """Verify required StorageClasses exist."""
    if not required:
        return

    result = shell.kubectl(
        "get", "storageclasses",
        "-o", "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise UpReadyError(
            f"Failed to query StorageClasses: {(result.stderr or '').strip()}"
        )

    try:
        payload = json.loads(result.stdout or "{}")
        available = set()
        for sc in payload.get("items", []):
            name = (sc.get("metadata") or {}).get("name")
            if name:
                available.add(name)
    except json.JSONDecodeError:
        raise UpReadyError("Failed to parse StorageClasses")

    missing = [name for name in required if name not in available]
    if missing:
        raise UpReadyError(
            f"Missing required StorageClasses: {', '.join(missing)}. "
            f"Available: {', '.join(sorted(available))}"
        )
    step("S01", f"storage_classes: {len(required)} required class(es) present")


def check_secrets(ctx: UpReadyContext, required: list[SecretSpec]) -> None:
    """Verify required Secrets exist with expected keys."""
    if not required:
        return

    missing: list[str] = []
    for secret in required:
        result = shell.kubectl(
            "get", "secret", secret.name,
            "--namespace", secret.namespace,
            "-o", "json",
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            missing.append(f"{secret.namespace}/{secret.name}")
            continue

        if secret.key:
            try:
                data = json.loads(result.stdout).get("data", {})
                if secret.key not in data or not data[secret.key]:
                    missing.append(
                        f"{secret.namespace}/{secret.name} (key={secret.key})"
                    )
            except (json.JSONDecodeError, TypeError):
                missing.append(f"{secret.namespace}/{secret.name}")

    if missing:
        raise UpReadyError(
            f"Missing {len(missing)} required Secret(s): {', '.join(missing)}"
        )
    step("S01", f"secrets: {len(required)} required secret(s) present")


def check_service_accounts(ctx: UpReadyContext, required: list[str]) -> None:
    """Verify required ServiceAccounts exist."""
    if not required:
        return

    missing: list[str] = []
    for name in required:
        parts = name.split("/", 1)
        namespace = parts[0] if len(parts) == 2 else ctx.settings.kube_namespace
        sa_name = parts[-1]

        result = shell.kubectl(
            "get", "serviceaccount", sa_name,
            "--namespace", namespace,
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            missing.append(name)

    if missing:
        raise UpReadyError(
            f"Missing required ServiceAccount(s): {', '.join(missing)}"
        )
    step("S01", f"service_accounts: {len(required)} required SA(s) present")


def check_host_devices(ctx: UpReadyContext, devices: list[str]) -> None:
    """Reject legacy device probes; device health is a sensor readiness gate."""
    if not devices:
        return

    raise UpReadyError(
        "host_devices preflight probes are unsupported; declare node labels or "
        "advertised resources and use sensor readiness for final device health"
    )


def check_crds(ctx: UpReadyContext, required: list[str]) -> None:
    """Verify required CRDs exist."""
    if not required:
        return

    result = shell.kubectl(
        "get", "crds",
        "-o", "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise UpReadyError(
            f"Failed to query CRDs: {(result.stderr or '').strip()}"
        )

    try:
        payload = json.loads(result.stdout or "{}")
        available = set()
        for crd in payload.get("items", []):
            name = (crd.get("metadata") or {}).get("name")
            if name:
                available.add(name)
    except json.JSONDecodeError:
        raise UpReadyError("Failed to parse CRDs")

    missing = [name for name in required if name not in available]
    if missing:
        raise UpReadyError(
            f"Missing required CRD(s): {', '.join(missing)}"
        )
    step("S01", f"crds: {len(required)} required CRD(s) present")


def check_disk_space(ctx: UpReadyContext, min_gb: int | None) -> None:
    """Validate advertised ephemeral-storage capacity without debug pods."""
    if min_gb is None:
        return

    result = shell.kubectl(
        "get", "nodes",
        "-o", "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        warn("could not query nodes for disk space check")
        return

    try:
        nodes = json.loads(result.stdout or "{}").get("items", [])
    except json.JSONDecodeError as exc:
        raise UpReadyError("Failed to parse node capacity") from exc
    minimum_kib = min_gb * 1024 * 1024
    for node in nodes:
        node_name = (node.get("metadata") or {}).get("name", "unknown")
        raw = (node.get("status") or {}).get("capacity", {}).get("ephemeral-storage", "0")
        match = re.fullmatch(r"(\d+)Ki", str(raw))
        if not match or int(match.group(1)) < minimum_kib:
            raise UpReadyError(
                f"Node {node_name} advertises insufficient ephemeral-storage: {raw}"
            )
    step("S01", f"disk_capacity: {min_gb}Gi advertised minimum verified")


def check_conflicting_release(ctx: UpReadyContext, check_enabled: bool) -> None:
    """Check for umbrella release that might conflict with split deployment."""
    if not check_enabled:
        return

    result = shell.helm(
        "list",
        "--namespace", ctx.settings.kube_namespace,
        "--filter", ctx.settings.helm_release,
        "-o", "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        return

    try:
        releases = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return

    if not releases:
        return

    release = next(
        (item for item in releases if item.get("name") == ctx.settings.helm_release),
        None,
    )
    if release is None:
        return
    status = release.get("status", "")

    if status == "deployed":
        raise UpReadyError(
            f"Helm release {ctx.settings.helm_release!r} already exists with "
            f"status={status}; use an approved stack cutover plan for ownership migration"
        )


def cluster_preflight(ctx: UpReadyContext) -> None:
    """Run all cluster preflight checks. Raises UpReadyError on failure."""
    spec = _load_preflight_spec()
    check_api_connectivity(ctx)
    check_nodes_ready(ctx, spec.cluster.minimum_ready_nodes)
    check_node_requirements(ctx, spec.node_requirements)
    check_storage_classes(ctx, spec.storage_classes)
    check_secrets(ctx, spec.secrets)
    check_service_accounts(ctx, spec.service_accounts)
    check_host_devices(ctx, spec.host_devices)
    check_crds(ctx, spec.crds)
    check_disk_space(ctx, spec.min_disk_space_gb)
    check_conflicting_release(ctx, spec.conflicting_releases)
