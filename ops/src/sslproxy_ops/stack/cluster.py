"""Read-only cluster preflight, status, and smoke checks."""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from .core import StackConfig
from .gates import _resolve_gate_resource
from .shell import helm, kubectl


@dataclass(frozen=True)
class CheckResult:
    subject: str
    healthy: bool
    detail: str


def _json_result(result: Any, subject: str) -> dict[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(f"{subject}: {(result.stderr or '').strip()}")
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{subject}: invalid JSON output") from exc


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise RuntimeError(f"unrecognized tool version: {value!r}")
    return tuple(int(item or 0) for item in match.groups())  # type: ignore[return-value]


def _storage_bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)(Ki|Mi|Gi|Ti|K|M|G|T)?", value)
    if not match:
        raise RuntimeError(f"unrecognized Kubernetes storage quantity: {value!r}")
    amount = int(match.group(1))
    suffix = match.group(2) or ""
    powers = {
        "": 1,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
    }
    return amount * powers[suffix]


def preflight(
    config: StackConfig,
    root_dir: Path,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> list[CheckResult]:
    """Validate tools, context, nodes, prerequisites, and exact ownership conflicts."""

    results: list[CheckResult] = []
    for tool in ("helm", "kubectl"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required tool not found: {tool}")
        results.append(CheckResult(f"tool/{tool}", True, "found"))
    helm_version = helm(
        "version",
        "--template",
        "{{.Version}}",
        check=False,
    )
    if helm_version.returncode != 0 or _version_tuple(helm_version.stdout) < (3, 17, 0):
        raise RuntimeError("Helm 3.17.0 or newer is required")
    results.append(CheckResult("tool/helm-version", True, helm_version.stdout.strip()))
    kubectl_version = kubectl(
        "version",
        "--client",
        "-o",
        "json",
        kubeconfig=kubeconfig,
        check=False,
    )
    version_payload = _json_result(kubectl_version, "kubectl version")
    client_version = version_payload.get("clientVersion", {}).get("gitVersion", "")
    if _version_tuple(client_version) < (1, 28, 0):
        raise RuntimeError("kubectl 1.28.0 or newer is required")
    results.append(CheckResult("tool/kubectl-version", True, client_version))

    if context:
        contexts = kubectl(
            "config",
            "get-contexts",
            "-o",
            "name",
            kubeconfig=kubeconfig,
            check=False,
        )
        available = set((contexts.stdout or "").splitlines())
        if context not in available:
            raise RuntimeError(f"Kubernetes context does not exist: {context}")
    api = kubectl(
        "get",
        "nodes",
        "-o",
        "json",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    nodes = _json_result(api, "nodes").get("items", [])
    ready = 0
    for node in nodes:
        node_name = node.get("metadata", {}).get("name", "unknown")
        conditions = {
            item.get("type"): item.get("status")
            for item in node.get("status", {}).get("conditions", [])
        }
        if conditions.get("DiskPressure") != "False":
            raise RuntimeError(f"node/{node_name} DiskPressure is not False")
        if conditions.get("Ready") == "True":
            ready += 1
    if ready < 1:
        raise RuntimeError("no Ready Kubernetes nodes")
    results.append(CheckResult("nodes", True, f"{ready} Ready"))

    spec_path = (
        root_dir / "ops" / "src" / "sslproxy_ops" / "commands" / "up_ready" / "preflight_spec.yaml"
    )
    spec = yaml.safe_load(spec_path.read_text()).get("preflight", {})
    minimum_disk_gb = spec.get("min_disk_space_gb")
    if minimum_disk_gb:
        minimum_bytes = int(minimum_disk_gb) * 1024**3
        for node in nodes:
            node_name = node.get("metadata", {}).get("name", "unknown")
            advertised = node.get("status", {}).get("capacity", {}).get("ephemeral-storage", "0")
            if _storage_bytes(advertised) < minimum_bytes:
                raise RuntimeError(
                    f"node/{node_name} advertises less than {minimum_disk_gb}Gi ephemeral-storage"
                )
        results.append(
            CheckResult(
                "node-capacity/ephemeral-storage",
                True,
                f">={minimum_disk_gb}Gi advertised",
            )
        )
    for workload, requirement in spec.get("node_requirements", {}).items():
        labels = requirement.get("labels", {})
        matching = [
            node
            for node in nodes
            if all(
                node.get("metadata", {}).get("labels", {}).get(key) == value
                for key, value in labels.items()
            )
        ]
        if not matching:
            raise RuntimeError(f"{workload}: no node satisfies labels {labels}")
        results.append(CheckResult(f"node-labels/{workload}", True, str(labels)))

    storage = _json_result(
        kubectl(
            "get",
            "storageclasses",
            "-o",
            "json",
            context=context,
            kubeconfig=kubeconfig,
            check=False,
        ),
        "storageclasses",
    )
    available_storage = {item.get("metadata", {}).get("name") for item in storage.get("items", [])}
    for required in spec.get("storage_classes", []):
        if required not in available_storage:
            raise RuntimeError(f"missing StorageClass/{required}")
        results.append(CheckResult(f"storageclass/{required}", True, "present"))

    for secret in spec.get("secrets", []):
        secret_namespace = secret.get("namespace", namespace)
        name = secret["name"]
        payload = _json_result(
            kubectl(
                "get",
                "secret",
                name,
                "-n",
                secret_namespace,
                "-o",
                "json",
                context=context,
                kubeconfig=kubeconfig,
                check=False,
            ),
            f"Secret/{secret_namespace}/{name}",
        )
        key = secret.get("key")
        if key and not payload.get("data", {}).get(key):
            raise RuntimeError(f"Secret/{secret_namespace}/{name} lacks key {key!r}")
        results.append(CheckResult(f"secret/{name}", True, f"key={key}"))

    for crd in spec.get("crds", []):
        result = kubectl(
            "get",
            "crd",
            crd,
            context=context,
            kubeconfig=kubeconfig,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"missing CustomResourceDefinition/{crd}")
        results.append(CheckResult(f"crd/{crd}", True, "present"))

    planned_releases = {
        component.release
        for component in config.components.values()
        if component.type in ("helm", "helm-job")
    }
    ownership = kubectl(
        "get",
        "all,configmap,serviceaccount,pvc",
        "-n",
        namespace,
        "-l",
        "app.kubernetes.io/instance=ssl-proxy",
        "-o",
        "json",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if ownership.returncode == 0:
        conflicts = []
        for item in _json_result(ownership, "ownership inventory").get("items", []):
            annotations = item.get("metadata", {}).get("annotations", {})
            owner = annotations.get("meta.helm.sh/release-name")
            if owner and owner not in planned_releases:
                conflicts.append(
                    f"{item.get('kind')}/{item.get('metadata', {}).get('name')} owner={owner}"
                )
        if conflicts:
            raise RuntimeError("ownership conflicts require cutover plan: " + ", ".join(conflicts))
    results.append(CheckResult("ownership", True, "no unplanned owners"))
    return results


def _resource_ready(resource: dict[str, Any]) -> tuple[bool, str]:
    kind = resource.get("kind")
    spec = resource.get("spec", {})
    status = resource.get("status", {})
    if kind == "Deployment":
        desired = spec.get("replicas", 1)
        ready = status.get("readyReplicas", 0)
        return ready >= desired, f"{ready}/{desired} ready"
    if kind == "StatefulSet":
        desired = spec.get("replicas", 1)
        ready = status.get("readyReplicas", 0)
        return ready >= desired, f"{ready}/{desired} ready"
    if kind == "DaemonSet":
        desired = status.get("desiredNumberScheduled", 0)
        ready = status.get("numberReady", 0)
        return desired > 0 and ready >= desired, f"{ready}/{desired} ready"
    if kind == "Job":
        conditions = {item.get("type"): item.get("status") for item in status.get("conditions", [])}
        return conditions.get("Complete") == "True", str(conditions)
    return True, "exists"


def status(
    config: StackConfig,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> list[CheckResult]:
    """Return release and configured gate health without mutating the cluster."""

    results: list[CheckResult] = []
    for name, component in config.components.items():
        if component.type in ("helm", "helm-job"):
            release = helm(
                "status",
                component.release,
                "-n",
                namespace,
                "-o",
                "json",
                context=context,
                kubeconfig=kubeconfig,
                check=False,
            )
            if release.returncode != 0:
                results.append(CheckResult(f"release/{name}", False, "not found"))
                continue
            payload = _json_result(release, f"release/{name}")
            release_status = payload.get("info", {}).get("status", "unknown")
            results.append(
                CheckResult(
                    f"release/{name}",
                    release_status == "deployed",
                    release_status,
                )
            )
        for gate in component.gates:
            try:
                reference = _resolve_gate_resource(
                    gate,
                    getattr(component, "release", name),
                    namespace,
                    context,
                    kubeconfig,
                )
            except RuntimeError as exc:
                results.append(CheckResult(f"gate/{name}", False, str(exc)))
                continue
            if not reference:
                results.append(CheckResult(f"gate/{name}", False, "not found"))
                continue
            resource = kubectl(
                "get",
                reference,
                "-n",
                namespace,
                "-o",
                "json",
                context=context,
                kubeconfig=kubeconfig,
                check=False,
            )
            if resource.returncode != 0:
                results.append(CheckResult(f"gate/{name}", False, "not found"))
                continue
            healthy, detail = _resource_ready(_json_result(resource, f"gate/{name}"))
            results.append(CheckResult(f"gate/{name}", healthy, detail))
    return results


def results_json(results: list[CheckResult]) -> str:
    return json.dumps([asdict(result) for result in results], indent=2, sort_keys=True)


def _kubectl_base(context: str | None, kubeconfig: str | None) -> list[str]:
    command = ["kubectl"]
    if kubeconfig:
        command.extend(["--kubeconfig", kubeconfig])
    elif context:
        command.extend(["--context", context])
    return command


def _forwarded_check(
    target: str,
    remote_port: int,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
    callback: Any,
) -> None:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        local_port = reservation.getsockname()[1]
    command = _kubectl_base(context, kubeconfig)
    command.extend(
        [
            "port-forward",
            target,
            f"{local_port}:{remote_port}",
            "-n",
            namespace,
            "--address",
            "127.0.0.1",
        ]
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, stderr = process.communicate()
                raise RuntimeError(f"port-forward failed: {stderr.strip()}")
            try:
                callback(local_port)
                return
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
                time.sleep(0.2)
        raise RuntimeError(f"port-forward check timed out: {last_error}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def smoke(
    config: StackConfig,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> list[CheckResult]:
    """Run configured bounded checks without creating diagnostic workloads."""

    results: list[CheckResult] = []
    for component_name, component in config.components.items():
        for index, check in enumerate(component.checks, 1):
            subject = f"check/{component_name}/{index}"
            try:
                if check.type == "resource":
                    response = kubectl(
                        "get",
                        check.target,
                        "-n",
                        namespace,
                        "-o",
                        "json",
                        context=context,
                        kubeconfig=kubeconfig,
                        check=False,
                    )
                    payload = _json_result(response, subject)
                    healthy, detail = _resource_ready(payload)
                    if not healthy:
                        raise RuntimeError(detail)
                elif check.type == "exec":
                    if not check.command:
                        raise RuntimeError("exec check requires command")
                    response = kubectl(
                        "exec",
                        check.target,
                        "-n",
                        namespace,
                        "--",
                        *check.command,
                        context=context,
                        kubeconfig=kubeconfig,
                        check=False,
                    )
                    if response.returncode != 0:
                        raise RuntimeError((response.stderr or "").strip())
                    detail = "exec succeeded"
                elif check.type == "http":
                    if check.port is None:
                        raise RuntimeError("http check requires port")
                    check_path = check.path or "/"

                    def http_callback(local_port: int, path: str = check_path) -> None:
                        url = f"http://127.0.0.1:{local_port}{path}"
                        with urllib.request.urlopen(url, timeout=2) as response:
                            if response.status < 200 or response.status >= 400:
                                raise RuntimeError(f"HTTP {response.status}")

                    _forwarded_check(
                        check.target,
                        check.port,
                        namespace,
                        context,
                        kubeconfig,
                        http_callback,
                    )
                    detail = "HTTP healthy"
                elif check.type == "tcp":
                    if check.port is None:
                        raise RuntimeError("tcp check requires port")

                    def tcp_callback(local_port: int) -> None:
                        with socket.create_connection(("127.0.0.1", local_port), timeout=2):
                            return

                    if "/" in check.target:
                        _forwarded_check(
                            check.target,
                            check.port,
                            namespace,
                            context,
                            kubeconfig,
                            tcp_callback,
                        )
                    else:
                        with socket.create_connection((check.target, check.port), timeout=3):
                            pass
                    detail = "TCP reachable"
                else:
                    raise RuntimeError(f"unsupported check type {check.type}")
                results.append(CheckResult(subject, True, detail))
            except Exception as exc:
                results.append(CheckResult(subject, False, str(exc)))
    return results


def smoke_component(
    component_name: str,
    config: StackConfig,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> list[CheckResult]:
    """Run only one component's configured checks."""

    component = config.components[component_name]
    scoped = config.model_copy(
        update={"components": {component_name: component}},
        deep=True,
    )
    return smoke(scoped, namespace, context, kubeconfig)


def component_health(
    config: StackConfig,
    names: set[str],
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> dict[str, bool]:
    """Return aggregate, read-only health for selected components."""

    health: dict[str, bool] = {}
    for name in names:
        component = config.components[name]
        scoped = config.model_copy(
            update={"components": {name: component}},
            deep=True,
        )
        results = status(scoped, namespace, context, kubeconfig)
        if component.type == "external-check":
            results.extend(smoke(scoped, namespace, context, kubeconfig))
        health[name] = bool(results) and all(item.healthy for item in results)
    return health
