"""Offline kustomize rendering, structural validation, and umbrella parity."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .core import StackConfig, generate_effective_values
from .shell import kustomize_build


@dataclass(frozen=True)
class RenderedComponent:
    name: str
    manifest: str
    resources: list[dict[str, Any]]
    effective_values: dict[str, Any]


def parse_manifest(text: str, source: str) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for index, document in enumerate(yaml.safe_load_all(text), 1):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise ValueError(f"{source} document {index} is not a YAML object")
        if not document.get("apiVersion") or not document.get("kind"):
            raise ValueError(f"{source} document {index} lacks apiVersion or kind")
        metadata = document.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("name"):
            raise ValueError(f"{source} document {index} lacks metadata.name")
        resources.append(document)
    if not resources:
        raise ValueError(f"{source} rendered no resources")
    return resources


def resource_identity(resource: dict[str, Any]) -> tuple[str, str, str, str]:
    api_version = str(resource["apiVersion"])
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    metadata = resource["metadata"]
    return (
        group,
        str(resource["kind"]),
        str(metadata.get("namespace", "")),
        str(metadata["name"]),
    )


def render_component(
    name: str,
    config: StackConfig,
    root_dir: Path,
    umbrella_values: list[dict[str, Any]],
    runtime_overrides: dict[str, Any] | None = None,
    namespace: str | None = None,
) -> RenderedComponent:
    component = config.components[name]
    if component.type not in ("helm", "helm-job"):
        raise ValueError(f"Offline rendering for {component.type!r} is not implemented")
    overlay_path = f"cyber-stack/base/{name}"
    with tempfile.TemporaryDirectory(prefix=f"stackctl-render-{name}-") as temp_dir:
        temp = Path(temp_dir)
        overlay_src = Path(root_dir) / overlay_path
        if not overlay_src.is_dir():
            raise FileNotFoundError(f"Component overlay not found: {overlay_src}")
        overlay_dest = temp / "overlay"
        shutil.copytree(overlay_src, overlay_dest)
        effective = generate_effective_values(
            config,
            name,
            umbrella_values,
            runtime_overrides=runtime_overrides,
            root_dir=root_dir,
        )
        values_yaml = yaml.safe_dump(effective, default_flow_style=False)
        (temp / "values.yaml").write_text(values_yaml)
        os.chmod(temp / "values.yaml", 0o600)
        kustomization = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["overlay"],
            "configMapGenerator": [
                {
                    "name": f"{name}-effective-values",
                    "files": ["values.yaml"],
                }
            ],
        }
        (temp / "kustomization.yaml").write_text(yaml.safe_dump(kustomization))
        result = kustomize_build(str(temp))
    resources = parse_manifest(result.stdout, name)
    return RenderedComponent(name, result.stdout, resources, effective)


OVERLAY_MAP = {
    "prod-ssl-proxy": "cyber-stack/matrix/prod",
    "dev-ssl-proxy": "cyber-stack/matrix/dev",
}


def render_umbrella(
    umbrella_values: list[dict[str, Any]],
    runtime_overrides: dict[str, Any] | None,
    namespace: str,
) -> list[dict[str, Any]]:
    """Render the normalized umbrella baseline via kustomize."""

    if runtime_overrides:
        raise ValueError("runtime_overrides are not supported for umbrella rendering")
    for values in umbrella_values:
        if values:
            raise ValueError("umbrella_values are not supported for umbrella rendering")
    overlay = OVERLAY_MAP.get(namespace)
    if overlay is None:
        raise ValueError(
            f"namespace {namespace!r} has no configured kustomize overlay; "
            f"known overlays: {', '.join(sorted(OVERLAY_MAP))}"
        )
    result = kustomize_build(overlay)
    return parse_manifest(result.stdout, "umbrella")


def _selector_matches(labels: dict[str, Any], selector: str) -> bool:
    for expression in selector.split(","):
        if "=" not in expression:
            raise ValueError(f"Only equality selectors are supported: {selector!r}")
        key, value = expression.split("=", 1)
        if str(labels.get(key.strip(), "")) != value.strip():
            return False
    return True


def _kind_matches(rendered_kind: str, configured_kind: str) -> bool:
    rendered = rendered_kind.lower()
    configured = configured_kind.lower().removesuffix("s")
    return rendered == configured


def _pod_template(resource: dict[str, Any]) -> dict[str, Any] | None:
    kind = resource["kind"]
    spec = resource.get("spec", {})
    if kind == "CronJob":
        return spec.get("jobTemplate", {}).get("spec", {}).get("template")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}:
        return spec.get("template")
    return None


def validate_rendered(
    rendered: Iterable[RenderedComponent],
    config: StackConfig,
) -> list[str]:
    """Validate cross-release Kubernetes identities and workload invariants."""

    errors: list[str] = []
    all_resources: list[tuple[str, dict[str, Any]]] = []
    identities: dict[tuple[str, str, str, str], str] = {}
    by_component: dict[str, list[dict[str, Any]]] = {}
    for item in rendered:
        by_component[item.name] = item.resources
        for resource in item.resources:
            identity = resource_identity(resource)
            if identity in identities:
                errors.append(
                    f"resource collision {identity}: {identities[identity]} and {item.name}"
                )
            identities[identity] = item.name
            all_resources.append((item.name, resource))
            if "{{" in item.manifest:
                errors.append(f"{item.name} contains an unresolved template expression")

            template = _pod_template(resource)
            selector = resource.get("spec", {}).get("selector", {}).get("matchLabels")
            if selector and template:
                labels = template.get("metadata", {}).get("labels", {})
                missing = {
                    key: value for key, value in selector.items() if labels.get(key) != value
                }
                if missing:
                    errors.append(
                        f"{item.name} {resource['kind']}/{resource['metadata']['name']} "
                        "selector does not match pod-template labels"
                    )

    services = {
        resource["metadata"]["name"]
        for _, resource in all_resources
        if resource["kind"] == "Service"
    }
    configmaps = {
        resource["metadata"]["name"]
        for _, resource in all_resources
        if resource["kind"] == "ConfigMap"
    }
    for name, resource in all_resources:
        if resource["kind"] == "StatefulSet":
            service_name = resource.get("spec", {}).get("serviceName")
            if service_name and service_name not in services:
                errors.append(
                    f"{name} StatefulSet/{resource['metadata']['name']} references "
                    f"missing Service/{service_name}"
                )
        template = _pod_template(resource)
        if not template:
            continue
        pod_spec = template.get("spec", {})
        for volume in pod_spec.get("volumes", []):
            reference = volume.get("configMap", {}).get("name")
            if reference and reference.startswith("ssl-proxy") and reference not in configmaps:
                errors.append(
                    f"{name} {resource['kind']}/{resource['metadata']['name']} "
                    f"references missing ConfigMap/{reference}"
                )

    for name, component in config.components.items():
        resources = by_component.get(name, [])
        for gate in component.gates:
            matches: list[dict[str, Any]]
            if gate.resource:
                kind, resource_name = gate.resource.split("/", 1)
                matches = [
                    resource
                    for resource in resources
                    if _kind_matches(resource["kind"], kind)
                    and resource["metadata"]["name"] == resource_name
                ]
            else:
                assert gate.discover is not None
                matches = [
                    resource
                    for resource in resources
                    if _kind_matches(resource["kind"], gate.discover["kind"])
                    and _selector_matches(
                        resource.get("metadata", {}).get("labels", {}),
                        gate.discover["selector"],
                    )
                ]
            if len(matches) != 1:
                errors.append(
                    f"{name} gate matched {len(matches)} rendered resources; expected exactly one"
                )
    return errors


def normalize_resource(resource: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(resource)
    metadata = normalized.get("metadata", {})
    metadata.pop("creationTimestamp", None)
    labels = metadata.get("labels", {})
    labels.pop("helm.sh/chart", None)
    if not labels:
        metadata.pop("labels", None)
    annotations = metadata.get("annotations", {})
    for key in (
        "meta.helm.sh/release-name",
        "meta.helm.sh/release-namespace",
    ):
        annotations.pop(key, None)
    if not annotations:
        metadata.pop("annotations", None)
    return normalized


def parity_diff(
    umbrella_resources: list[dict[str, Any]],
    split_resources: list[dict[str, Any]],
) -> list[str]:
    """Return unapproved umbrella/split manifest differences."""

    def approved(resource: dict[str, Any]) -> bool:
        labels = resource.get("metadata", {}).get("labels", {})
        name = resource.get("metadata", {}).get("name", "")
        if (
            resource.get("kind") == "Job"
            and labels.get("app.kubernetes.io/name") == "tidb-schema-executor"
        ):
            return True
        if resource.get("kind") == "ConfigMap" and name.endswith("-effective-values"):
            return True
        return False

    umbrella = {
        resource_identity(resource): normalize_resource(resource)
        for resource in umbrella_resources
        if not approved(resource)
    }
    split = {
        resource_identity(resource): normalize_resource(resource)
        for resource in split_resources
        if not approved(resource)
    }
    errors: list[str] = []
    for identity in sorted(set(umbrella) | set(split)):
        if identity not in umbrella:
            errors.append(f"split-only resource: {identity}")
        elif identity not in split:
            errors.append(f"umbrella-only resource: {identity}")
        elif umbrella[identity] != split[identity]:
            errors.append(f"manifest differs: {identity}")
    return errors


def safe_artifact_dir(root_dir: Path, configured: str | Path) -> Path:
    raw = Path(configured)
    path = raw if raw.is_absolute() else root_dir / raw
    root = root_dir.resolve()
    unresolved = path.absolute()
    for candidate in (unresolved, *unresolved.parents):
        if candidate == root.parent:
            break
        if candidate.is_symlink():
            raise ValueError("artifact directory cannot contain symlinks")
    parent = path.parent.resolve()
    if root not in (parent, *parent.parents):
        raise ValueError("artifact directory must stay within the repository root")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def write_render_artifacts(
    directory: Path,
    rendered: Iterable[RenderedComponent],
    redactor: Any,
) -> None:
    for item in rendered:
        manifest_path = directory / f"{item.name}.yaml"
        manifest_path.write_text(item.manifest)
        os.chmod(manifest_path, 0o600)
        values_path = directory / f"{item.name}.values.redacted.json"
        values_path.write_text(
            json.dumps(redactor(item.effective_values), indent=2, sort_keys=True) + "\n"
        )
        os.chmod(values_path, 0o600)


def _tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
    for item in files:
        digest.update(str(item.relative_to(path.parent if path.is_file() else path)).encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _redact_parity_resource(resource: dict[str, Any], redactor: Any) -> dict[str, Any]:
    safe = copy.deepcopy(resource)
    if safe.get("kind") == "Secret":
        safe.pop("data", None)
        safe.pop("stringData", None)
    return redactor(safe)


def write_parity_artifacts(
    directory: Path,
    config: StackConfig,
    root_dir: Path,
    umbrella: list[dict[str, Any]],
    split: list[RenderedComponent],
    differences: list[str],
    redactor: Any,
) -> None:
    """Capture the normalized parity baseline, hashes, and resource inventory."""

    normalized_umbrella = [normalize_resource(item) for item in umbrella]
    normalized_split = [
        normalize_resource(resource) for component in split for resource in component.resources
    ]
    for name, resources in (
        ("umbrella.normalized.yaml", normalized_umbrella),
        ("split.normalized.yaml", normalized_split),
    ):
        path = directory / name
        path.write_text(
            yaml.safe_dump_all(
                (_redact_parity_resource(item, redactor) for item in resources),
                sort_keys=True,
            )
        )
        os.chmod(path, 0o600)

    charts = {
        "umbrella": _tree_digest(root_dir / "helm" / "ssl-proxy"),
        **{
            name: _tree_digest(root_dir / component.chart)
            for name, component in config.components.items()
            if component.type in ("helm", "helm-job")
        },
    }
    values = {
        configured: _tree_digest(
            Path(configured) if Path(configured).is_absolute() else root_dir / configured
        )
        for configured in config.defaults.values
    }
    payload = {
        "parity": not differences,
        "differences": differences,
        "mode_decision": {
            "redpanda": "in-cluster",
            "minio": "in-cluster",
        },
        "chart_hashes": charts,
        "value_hashes": values,
        "resources": [
            {
                "group": identity[0],
                "kind": identity[1],
                "namespace": identity[2],
                "name": identity[3],
            }
            for identity in sorted(resource_identity(item) for item in umbrella)
        ],
    }
    path = directory / "baseline.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o600)
