#!/usr/bin/env python3
"""Produce a read-only GitOps, Kubernetes, and image recovery report."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from image_contract import (
    ENVIRONMENTS,
    ImageContract,
    ImageContractError,
    load_image_contracts,
    split_registry_repository,
)
from platform_input_contract import (
    PlatformInputContract,
    PlatformInputContractError,
    load_platform_input_contract,
)


CANONICAL_SLICES = ("bootstrap", "data-plane", "app-stack")
# The Makefile's default `git rev-parse --short` contract is at least 7 chars.
MIN_GIT_ABBREVIATION_LENGTH = 7
REGISTRY_LOOKUP_WORKER_LIMIT = 8
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
PRESENT_MARKER = "__SSL_PROXY_PRESENT__"
SECRET_KEY_NAMES_TEMPLATE = (
    '{{printf "__SSL_PROXY_PRESENT__\\t%s\\n" .type}}'
    '{{range $key, $_ := .data}}{{println $key}}{{end}}'
)
CONFIG_MAP_KEY_NAMES_TEMPLATE = (
    '{{println "__SSL_PROXY_PRESENT__"}}'
    '{{range $key, $_ := .data}}{{println $key}}{{end}}'
    '{{range $key, $_ := .binaryData}}{{println $key}}{{end}}'
)


def argo_applications_for(environment: str) -> dict[str, str]:
    return {
        f"ssl-proxy-{environment}-{component}":
        f"cyber-stack/matrix/{environment}/{component}"
        for component in CANONICAL_SLICES
    }


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[Sequence[str], Path], CommandResult]


@dataclass(frozen=True, order=True)
class DesiredImage:
    slice_name: str
    kind: str
    namespace: str
    workload: str
    container_type: str
    container: str
    image: str

    @property
    def workload_key(self) -> tuple[str, str]:
        return self.kind, self.workload


@dataclass(frozen=True)
class RegistryTags:
    status: str
    tags: tuple[str, ...] = ()
    detail: str = ""


RegistryResolver = Callable[[ImageContract, bool], RegistryTags]


def _subprocess_runner(command: Sequence[str], repository_root: Path) -> CommandResult:
    result = subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return CommandResult(result.returncode, result.stdout, result.stderr)


def _short_error(result: CommandResult) -> str:
    detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
    return " ".join(detail.split())[:300]


def _load_yaml_documents(content: str, label: str) -> list[Mapping[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as error:
        raise ValueError(f"cannot parse {label}: {error}") from error
    return [document for document in documents if isinstance(document, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _pod_spec(document: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = document.get("kind")
    spec = _mapping(document.get("spec"))
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        return _mapping(_mapping(spec.get("template")).get("spec"))
    if kind == "CronJob":
        job_template = _mapping(spec.get("jobTemplate"))
        template = _mapping(_mapping(job_template.get("spec")).get("template"))
        return _mapping(template.get("spec"))
    if kind == "Pod":
        return spec
    return None


def _document_identity(document: Mapping[str, Any]) -> tuple[str, str, str]:
    metadata = _mapping(document.get("metadata"))
    return (
        str(document.get("kind", "Unknown")),
        str(metadata.get("namespace", "")),
        str(metadata.get("name", "<unnamed>")),
    )


def inventory_images(
    documents_by_slice: Mapping[str, Sequence[Mapping[str, Any]]], namespace: str
) -> list[DesiredImage]:
    images: list[DesiredImage] = []
    seen: set[DesiredImage] = set()
    for slice_name in CANONICAL_SLICES:
        for document in documents_by_slice.get(slice_name, ()):
            kind, document_namespace, name = _document_identity(document)
            pod_spec = _pod_spec(document)
            if pod_spec is None:
                continue
            for field, container_type in (
                ("initContainers", "init"),
                ("containers", "regular"),
            ):
                for container in _list(pod_spec.get(field)):
                    if not isinstance(container, Mapping):
                        continue
                    container_name = container.get("name")
                    image = container.get("image")
                    if not isinstance(container_name, str) or not isinstance(image, str):
                        continue
                    entry = DesiredImage(
                        slice_name=slice_name,
                        kind=kind,
                        namespace=document_namespace or namespace,
                        workload=name,
                        container_type=container_type,
                        container=container_name,
                        image=image,
                    )
                    if entry not in seen:
                        seen.add(entry)
                        images.append(entry)
    return sorted(images)


def _required_secrets_from_pod_spec(pod_spec: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for pull_secret in _list(pod_spec.get("imagePullSecrets")):
        if isinstance(pull_secret, Mapping) and isinstance(pull_secret.get("name"), str):
            names.add(pull_secret["name"])

    for volume in _list(pod_spec.get("volumes")):
        if not isinstance(volume, Mapping):
            continue
        secret = _mapping(volume.get("secret"))
        if secret.get("optional") is not True and isinstance(secret.get("secretName"), str):
            names.add(secret["secretName"])
        projected = _mapping(volume.get("projected"))
        for source in _list(projected.get("sources")):
            source_secret = _mapping(_mapping(source).get("secret"))
            if source_secret.get("optional") is not True and isinstance(
                source_secret.get("name"), str
            ):
                names.add(source_secret["name"])

    for field in ("initContainers", "containers"):
        for container in _list(pod_spec.get(field)):
            if not isinstance(container, Mapping):
                continue
            for env_from in _list(container.get("envFrom")):
                secret_ref = _mapping(_mapping(env_from).get("secretRef"))
                if secret_ref.get("optional") is not True and isinstance(
                    secret_ref.get("name"), str
                ):
                    names.add(secret_ref["name"])
            for variable in _list(container.get("env")):
                secret_ref = _mapping(
                    _mapping(_mapping(variable).get("valueFrom")).get("secretKeyRef")
                )
                if secret_ref.get("optional") is not True and isinstance(
                    secret_ref.get("name"), str
                ):
                    names.add(secret_ref["name"])
    return names


def inventory_required_secrets(
    documents_by_slice: Mapping[str, Sequence[Mapping[str, Any]]]
) -> list[str]:
    names: set[str] = set()
    for slice_name in CANONICAL_SLICES:
        for document in documents_by_slice.get(slice_name, ()):
            pod_spec = _pod_spec(document)
            if pod_spec is not None:
                names.update(_required_secrets_from_pod_spec(pod_spec))
            spec = _mapping(document.get("spec"))
            for tls in _list(spec.get("tls")):
                secret_name = _mapping(tls).get("secretName")
                if isinstance(secret_name, str):
                    names.add(secret_name)
    return sorted(names)


def _required_config_maps_from_pod_spec(pod_spec: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for volume in _list(pod_spec.get("volumes")):
        if not isinstance(volume, Mapping):
            continue
        config_map = _mapping(volume.get("configMap"))
        if config_map.get("optional") is not True and isinstance(
            config_map.get("name"), str
        ):
            names.add(config_map["name"])
        projected = _mapping(volume.get("projected"))
        for source in _list(projected.get("sources")):
            source_config_map = _mapping(_mapping(source).get("configMap"))
            if source_config_map.get("optional") is not True and isinstance(
                source_config_map.get("name"), str
            ):
                names.add(source_config_map["name"])

    for field in ("initContainers", "containers"):
        for container in _list(pod_spec.get(field)):
            if not isinstance(container, Mapping):
                continue
            for env_from in _list(container.get("envFrom")):
                config_map_ref = _mapping(_mapping(env_from).get("configMapRef"))
                if config_map_ref.get("optional") is not True and isinstance(
                    config_map_ref.get("name"), str
                ):
                    names.add(config_map_ref["name"])
            for variable in _list(container.get("env")):
                config_map_ref = _mapping(
                    _mapping(_mapping(variable).get("valueFrom")).get(
                        "configMapKeyRef"
                    )
                )
                if config_map_ref.get("optional") is not True and isinstance(
                    config_map_ref.get("name"), str
                ):
                    names.add(config_map_ref["name"])
    return names


def inventory_required_config_maps(
    documents_by_slice: Mapping[str, Sequence[Mapping[str, Any]]]
) -> list[str]:
    names: set[str] = set()
    for slice_name in CANONICAL_SLICES:
        for document in documents_by_slice.get(slice_name, ()):
            pod_spec = _pod_spec(document)
            if pod_spec is not None:
                names.update(_required_config_maps_from_pod_spec(pod_spec))
    return sorted(names)


def kustomize_build_command(executable: str, path: Path) -> tuple[str, ...]:
    if Path(executable).name == "kubectl":
        return (
            executable,
            "kustomize",
            str(path),
            "--load-restrictor",
            "LoadRestrictionsNone",
        )
    return (
        executable,
        "build",
        "--load-restrictor",
        "LoadRestrictionsNone",
        str(path),
    )


def _image_repository(reference: str) -> str:
    value = reference.split("//", 1)[-1]
    if "@" in value:
        return value.split("@", 1)[0]
    final_slash = value.rfind("/")
    final_colon = value.rfind(":")
    if final_colon > final_slash:
        return value[:final_colon]
    return value


def _runtime_manifest_digest(image_id: str) -> str | None:
    value = image_id.split("//", 1)[-1]
    if "@sha256:" not in value:
        return None
    digest = "sha256:" + value.split("@sha256:", 1)[1].split("/", 1)[0]
    if len(digest) == 71:
        return digest
    return None


def _registry_request(url: str, *, method: str = "GET") -> urllib.response.addinfourl:
    request = urllib.request.Request(url, method=method)
    request.add_header("Accept", MANIFEST_ACCEPT)
    return urllib.request.urlopen(request, timeout=3)


def resolve_registry_tags(contract: ImageContract, plain_http: bool) -> RegistryTags:
    registry, repository_path = split_registry_repository(contract.repository)
    scheme = "http" if plain_http else "https"
    encoded_repository = urllib.parse.quote(repository_path, safe="/")
    tags_url = f"{scheme}://{registry}/v2/{encoded_repository}/tags/list"
    try:
        with _registry_request(tags_url) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        return RegistryTags("UNKNOWN", detail=str(error))

    raw_tags = payload.get("tags", []) if isinstance(payload, Mapping) else []
    if raw_tags is None:
        raw_tags = []
    if not isinstance(raw_tags, list) or not all(isinstance(tag, str) for tag in raw_tags):
        return RegistryTags("UNKNOWN", detail="registry returned an invalid tag list")

    matching: list[str] = []
    resolved_any = not raw_tags
    for tag in raw_tags:
        encoded_tag = urllib.parse.quote(tag, safe="")
        manifest_url = f"{scheme}://{registry}/v2/{encoded_repository}/manifests/{encoded_tag}"
        try:
            with _registry_request(manifest_url, method="HEAD") as response:
                resolved = response.headers.get("Docker-Content-Digest")
        except urllib.error.HTTPError as error:
            if error.code != 405:
                continue
            try:
                with _registry_request(manifest_url) as response:
                    resolved = response.headers.get("Docker-Content-Digest")
            except (OSError, urllib.error.URLError, urllib.error.HTTPError):
                continue
        except (OSError, urllib.error.URLError):
            continue
        if resolved:
            resolved_any = True
            if resolved == contract.digest:
                matching.append(tag)
    if not resolved_any:
        return RegistryTags("UNKNOWN", detail="tag manifests did not expose digests")
    return RegistryTags("KNOWN", tuple(sorted(matching)))


def _container_map(pod_spec: Mapping[str, Any], container_type: str) -> dict[str, str]:
    field = "initContainers" if container_type == "init" else "containers"
    return {
        str(container.get("name")): str(container.get("image"))
        for container in _list(pod_spec.get(field))
        if isinstance(container, Mapping)
        and isinstance(container.get("name"), str)
        and isinstance(container.get("image"), str)
    }


def _workload_health(item: Mapping[str, Any]) -> tuple[str, str]:
    kind = str(item.get("kind", "Unknown"))
    spec = _mapping(item.get("spec"))
    status = _mapping(item.get("status"))
    desired = int(spec.get("replicas", 1) or 0)
    if kind == "Deployment":
        ready = int(status.get("readyReplicas", 0) or 0)
        available = int(status.get("availableReplicas", 0) or 0)
        updated = int(status.get("updatedReplicas", 0) or 0)
        healthy = ready >= desired and available >= desired and updated >= desired
        return ("HEALTHY" if healthy else "UNHEALTHY", f"ready={ready}/{desired} updated={updated}")
    if kind == "StatefulSet":
        ready = int(status.get("readyReplicas", 0) or 0)
        updated = int(status.get("updatedReplicas", 0) or 0)
        healthy = ready >= desired and updated >= desired
        return ("HEALTHY" if healthy else "UNHEALTHY", f"ready={ready}/{desired} updated={updated}")
    if kind == "DaemonSet":
        desired_nodes = int(status.get("desiredNumberScheduled", 0) or 0)
        ready = int(status.get("numberReady", 0) or 0)
        updated = int(status.get("updatedNumberScheduled", 0) or 0)
        healthy = ready >= desired_nodes and updated >= desired_nodes
        return (
            "HEALTHY" if healthy else "UNHEALTHY",
            f"ready={ready}/{desired_nodes} updated={updated}",
        )
    if kind == "Job":
        conditions = {
            str(condition.get("type")): str(condition.get("status"))
            for condition in _list(status.get("conditions"))
            if isinstance(condition, Mapping)
        }
        if conditions.get("Failed") == "True":
            return "UNHEALTHY", f"failed={status.get('failed', 0)}"
        if conditions.get("Complete") == "True" or int(status.get("succeeded", 0) or 0) > 0:
            return "HEALTHY", f"succeeded={status.get('succeeded', 0)}"
        return "PROGRESSING", f"active={status.get('active', 0)} failed={status.get('failed', 0)}"
    return "UNKNOWN", "unsupported workload kind"


def _pod_health(pod: Mapping[str, Any]) -> tuple[str, str]:
    metadata = _mapping(pod.get("metadata"))
    if metadata.get("deletionTimestamp"):
        return "TERMINATING", "deletion in progress"
    status = _mapping(pod.get("status"))
    phase = str(status.get("phase", "Unknown"))
    if phase == "Succeeded":
        return "HEALTHY", "phase=Succeeded"
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in _list(status.get("conditions"))
        if isinstance(condition, Mapping)
    )
    if phase == "Running" and ready:
        return "HEALTHY", "phase=Running ready=True"
    return "UNHEALTHY", f"phase={phase} ready={ready}"


class RecoveryReporter:
    def __init__(
        self,
        repository_root: Path,
        environment: str,
        kube_context: str,
        kustomize: str,
        registry_plain_http: bool,
        *,
        runner: CommandRunner = _subprocess_runner,
        registry_resolver: RegistryResolver = resolve_registry_tags,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.environment = environment
        self.requested_context = kube_context.strip()
        self.kustomize = kustomize
        self.registry_plain_http = registry_plain_http
        self.runner = runner
        self.registry_resolver = registry_resolver
        self.lines: list[str] = []
        self.blockers: list[str] = []
        self.cluster_available = False

    def _block(self, detail: str) -> None:
        if detail not in self.blockers:
            self.blockers.append(detail)

    def _run(self, *command: str) -> CommandResult:
        return self.runner(command, self.repository_root)

    def _kubectl(self, context: str, *arguments: str) -> CommandResult:
        return self._run("kubectl", "--context", context, *arguments)

    def _json_result(self, result: CommandResult, label: str) -> Mapping[str, Any] | None:
        if result.returncode != 0:
            self._block(f"{label} query failed: {_short_error(result)}")
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self._block(f"{label} returned invalid JSON: {error}")
            return None
        if not isinstance(value, Mapping):
            self._block(f"{label} did not return a JSON object")
            return None
        return value

    def _resolve_context(self) -> tuple[str, str]:
        if self.requested_context:
            context = self.requested_context
            source = "explicit KUBE_CONTEXT"
        else:
            result = self._run("kubectl", "config", "current-context")
            if result.returncode != 0 or not result.stdout.strip():
                self._block(
                    f"cannot resolve current Kubernetes context: {_short_error(result)}"
                )
                return "<unresolved>", "current context unavailable"
            context = result.stdout.strip()
            source = "kubectl current-context"

        configured = self._run(
            "kubectl", "config", "get-contexts", context, "-o", "name"
        )
        if configured.returncode != 0 or configured.stdout.strip() != context:
            available = self._run("kubectl", "config", "get-contexts", "-o", "name")
            names = ", ".join(available.stdout.split()) or "<none>"
            self._block(
                f'Kubernetes context "{context}" is not configured; available: {names}'
            )
            return "<unresolved>", f"{source} is unavailable"

        reachable = self._run(
            "kubectl",
            "--context",
            context,
            "version",
            "--request-timeout=5s",
            "-o",
            "json",
        )
        if reachable.returncode != 0:
            self._block(
                f"Kubernetes API is unreachable through context {context}: "
                f"{_short_error(reachable)}"
            )
            return context, f"{source}; API unavailable"

        self.cluster_available = True
        return context, source

    def _namespace(self) -> str:
        path = self.repository_root / "cyber-stack" / "matrix" / self.environment / "kustomization.yaml"
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            self._block(f"cannot read environment namespace from {path}: {error}")
            return f"{self.environment}-ssl-proxy"
        namespace = _mapping(document).get("namespace")
        if not isinstance(namespace, str) or not namespace:
            self._block(f"environment Kustomization has no namespace: {path}")
            return f"{self.environment}-ssl-proxy"
        return namespace

    def _render(self) -> tuple[dict[str, list[Mapping[str, Any]]], str]:
        rendered: dict[str, list[Mapping[str, Any]]] = {}
        matrix = self.repository_root / "cyber-stack" / "matrix" / self.environment
        self.lines.extend(("", "GIT / KUSTOMIZE"))
        head_result = self._run("git", "rev-parse", "HEAD")
        head = head_result.stdout.strip() if head_result.returncode == 0 else "UNKNOWN"
        dirty_result = self._run("git", "status", "--porcelain")
        dirty = "UNKNOWN" if dirty_result.returncode != 0 else ("DIRTY" if dirty_result.stdout else "clean")
        self.lines.append(f"  Git HEAD: {head}")
        self.lines.append(f"  Worktree: {dirty}")

        paths = [(slice_name, matrix / slice_name) for slice_name in CANONICAL_SLICES]
        paths.append(("aggregate", matrix))
        for label, path in paths:
            result = self._run(*kustomize_build_command(self.kustomize, path))
            if result.returncode != 0:
                self.lines.append(f"  Render {label}: ERROR {_short_error(result)}")
                self._block(f"Kustomize render failed for {label}")
                continue
            try:
                documents = _load_yaml_documents(result.stdout, f"{label} render")
            except ValueError as error:
                self.lines.append(f"  Render {label}: ERROR {error}")
                self._block(f"Kustomize render is invalid for {label}")
                continue
            rendered[label] = documents
            self.lines.append(f"  Render {label}: OK ({len(documents)} resources)")
        return rendered, head

    def _report_argo(self, context: str, git_head: str) -> None:
        self.lines.extend(("", "ARGO CD"))
        if self.environment == "dev":
            self.lines.append("  SKIPPED: dev Applications are prohibited on the production controller")
            return
        if not self.cluster_available:
            self.lines.append("  UNKNOWN: Kubernetes context or API is unavailable")
            return
        result = self._kubectl(
            context,
            "--namespace",
            "argocd",
            "get",
            "applications.argoproj.io",
            "--selector",
            "app.kubernetes.io/part-of=ssl-proxy",
            "-o",
            "json",
        )
        document = self._json_result(result, "Argo CD Applications")
        if document is None:
            self.lines.append(f"  UNKNOWN: {_short_error(result)}")
            return
        applications = {
            str(_mapping(item.get("metadata")).get("name")): item
            for item in _list(document.get("items"))
            if isinstance(item, Mapping)
        }
        for name, expected_path in argo_applications_for(self.environment).items():
            application = applications.get(name)
            if application is None:
                self.lines.append(f"  {name}: MISSING (expected path {expected_path})")
                self._block(f"Argo CD Application is missing: {name}")
                continue
            spec = _mapping(application.get("spec"))
            source = _mapping(spec.get("source"))
            status = _mapping(application.get("status"))
            sync = _mapping(status.get("sync"))
            health = _mapping(status.get("health"))
            path = str(source.get("path", "UNKNOWN"))
            revision = str(sync.get("revision", "UNKNOWN"))
            sync_status = str(sync.get("status", "Unknown"))
            health_status = str(health.get("status", "Unknown"))
            revision_match = (
                git_head != "UNKNOWN"
                and len(revision) >= MIN_GIT_ABBREVIATION_LENGTH
                and revision == git_head
            )
            if (
                git_head != "UNKNOWN"
                and len(revision) >= MIN_GIT_ABBREVIATION_LENGTH
                and git_head.startswith(revision)
            ):
                revision_match = True
            self.lines.append(
                f"  {name}: path={path} revision={revision} "
                f"local={'MATCH' if revision_match else 'DIFF'} "
                f"sync={sync_status} health={health_status}"
            )
            if path != expected_path:
                self._block(f"Argo CD Application path drift: {name} uses {path}")
            if sync_status != "Synced" or health_status != "Healthy":
                self._block(
                    f"Argo CD Application unhealthy: {name} sync={sync_status} health={health_status}"
                )

    def _report_registry(self, contracts: Sequence[ImageContract]) -> None:
        self.lines.extend(("", "FIRST-PARTY REGISTRY TAGS"))
        if not contracts:
            self.lines.append("  UNKNOWN: image contract is unavailable")
            return
        results: dict[str, RegistryTags] = {}
        worker_count = min(len(contracts), REGISTRY_LOOKUP_WORKER_LIMIT)
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                contract.service: executor.submit(
                    self.registry_resolver, contract, self.registry_plain_http
                )
                for contract in contracts
            }
            for service, future in futures.items():
                try:
                    results[service] = future.result()
                except Exception as error:  # Registry failures never stop the report.
                    results[service] = RegistryTags("UNKNOWN", detail=str(error))
        for contract in contracts:
            result = results[contract.service]
            if result.status == "UNKNOWN":
                detail = " ".join(result.detail.split())[:160]
                self.lines.append(
                    f"  {contract.service}: desired={contract.reference} tags=UNKNOWN ({detail})"
                )
            else:
                tags = ",".join(result.tags) if result.tags else "<none>"
                self.lines.append(
                    f"  {contract.service}: desired={contract.reference} tags={tags}"
                )

    def _report_secrets(
        self, context: str, namespace: str, required_secrets: Sequence[str]
    ) -> None:
        self.lines.extend(("", "REQUIRED SECRETS (names and presence only)"))
        if not required_secrets:
            self.lines.append("  <none discovered>")
            return
        if not self.cluster_available:
            for name in required_secrets:
                self.lines.append(f"  {name}: UNKNOWN")
            return
        for name in required_secrets:
            result = self._kubectl(
                context,
                "--namespace",
                namespace,
                "get",
                "secret",
                name,
                "--ignore-not-found",
                "-o",
                "name",
            )
            if result.returncode != 0:
                self.lines.append(f"  {name}: UNKNOWN ({_short_error(result)})")
                self._block(f"cannot verify required Secret {name}")
            elif result.stdout.strip():
                self.lines.append(f"  {name}: PRESENT")
            else:
                self.lines.append(f"  {name}: MISSING")
                self._block(f"required Secret is missing: {namespace}/{name}")

    def _report_config_maps(
        self, context: str, namespace: str, required_config_maps: Sequence[str]
    ) -> None:
        self.lines.extend(("", "REQUIRED CONFIGMAPS (names and presence only)"))
        if not required_config_maps:
            self.lines.append("  <none discovered>")
            return
        if not self.cluster_available:
            for name in required_config_maps:
                self.lines.append(f"  {name}: UNKNOWN")
            return
        for name in required_config_maps:
            result = self._kubectl(
                context,
                "--namespace",
                namespace,
                "get",
                "configmap",
                name,
                "--ignore-not-found",
                "-o",
                "name",
            )
            if result.returncode != 0:
                self.lines.append(f"  {name}: UNKNOWN ({_short_error(result)})")
                self._block(f"cannot verify required ConfigMap {name}")
            elif result.stdout.strip():
                self.lines.append(f"  {name}: PRESENT")
            else:
                self.lines.append(f"  {name}: MISSING")
                self._block(f"required ConfigMap is missing: {namespace}/{name}")

    def _report_platform_contract(
        self,
        context: str,
        contract: PlatformInputContract,
    ) -> None:
        self.lines.extend(
            (
                "",
                "REQUIRED PLATFORM INPUTS "
                "(contract names and key names only; values suppressed)",
            )
        )
        if not self.cluster_available:
            for entry in contract.inputs:
                self.lines.append(
                    f"  {entry.kind}/{entry.name}: UNKNOWN "
                    f"required-keys={','.join(entry.keys)}"
                )
            return

        for entry in contract.inputs:
            resource = "secret" if entry.kind == "Secret" else "configmap"
            template = (
                SECRET_KEY_NAMES_TEMPLATE
                if entry.kind == "Secret"
                else CONFIG_MAP_KEY_NAMES_TEMPLATE
            )
            result = self._kubectl(
                context,
                "--namespace",
                contract.namespace,
                "get",
                resource,
                entry.name,
                "--ignore-not-found",
                "-o",
                f"go-template={template}",
            )
            label = f"{entry.kind}/{entry.name}"
            if result.returncode != 0:
                self.lines.append(f"  {label}: UNKNOWN ({_short_error(result)})")
                self._block(f"cannot verify platform input {label}")
                continue
            output = result.stdout.splitlines()
            if not output or not output[0].startswith(PRESENT_MARKER):
                self.lines.append(
                    f"  {label}: MISSING required-keys={','.join(entry.keys)}"
                )
                self._block(
                    f"required platform input is missing: "
                    f"{contract.namespace}/{entry.kind}/{entry.name}"
                )
                continue

            secret_type = None
            if entry.kind == "Secret":
                marker_fields = output[0].split("\t", 1)
                secret_type = marker_fields[1] if len(marker_fields) == 2 else "UNKNOWN"
            present_keys = set(output[1:])
            missing_keys = [key for key in entry.keys if key not in present_keys]
            type_suffix = (
                f" type={secret_type}" if entry.kind == "Secret" else ""
            )
            if missing_keys:
                self.lines.append(
                    f"  {label}: PRESENT{type_suffix} "
                    f"missing-keys={','.join(missing_keys)}"
                )
                self._block(
                    f"required platform input keys are missing: "
                    f"{contract.namespace}/{entry.kind}/{entry.name} "
                    f"({', '.join(missing_keys)})"
                )
            else:
                self.lines.append(f"  {label}: PRESENT{type_suffix} keys=OK")
            if entry.kind == "Secret" and secret_type != entry.secret_type:
                self._block(
                    f"platform input type drift: {contract.namespace}/{label} "
                    f"expected {entry.secret_type}, got {secret_type}"
                )

    def _report_desired_images(self, desired_images: Sequence[DesiredImage]) -> None:
        self.lines.extend(("", "DESIRED IMAGE INVENTORY (regular and init containers)"))
        if not desired_images:
            self.lines.append("  <none rendered>")
            return
        for image in desired_images:
            self.lines.append(
                f"  {image.slice_name} {image.kind}/{image.workload} "
                f"{image.container_type}/{image.container}: {image.image}"
            )

    def _report_live_state(
        self,
        context: str,
        namespace: str,
        desired_images: Sequence[DesiredImage],
        contracts: Sequence[ImageContract],
    ) -> None:
        self.lines.extend(("", "LIVE WORKLOADS AND IMAGE DRIFT"))
        if not self.cluster_available:
            self.lines.append("  UNKNOWN: Kubernetes context or API is unavailable")
            return
        workloads_result = self._kubectl(
            context,
            "--namespace",
            namespace,
            "get",
            "deployments.apps,statefulsets.apps,daemonsets.apps,jobs.batch",
            "-o",
            "json",
        )
        workloads_document = self._json_result(workloads_result, "Kubernetes workloads")
        if workloads_document is None:
            self.lines.append(f"  UNKNOWN: {_short_error(workloads_result)}")
            return
        live_workloads = {
            (str(item.get("kind")), str(_mapping(item.get("metadata")).get("name"))): item
            for item in _list(workloads_document.get("items"))
            if isinstance(item, Mapping)
        }
        desired_workload_keys = {image.workload_key for image in desired_images}
        for key in sorted(live_workloads):
            item = live_workloads[key]
            status, detail = _workload_health(item)
            self.lines.append(f"  {key[0]}/{key[1]}: {status} ({detail})")
            if status == "UNHEALTHY" and key in desired_workload_keys:
                self._block(f"workload is unhealthy: {namespace}/{key[0]}/{key[1]}")

        for desired in desired_images:
            live = live_workloads.get(desired.workload_key)
            if live is None:
                if desired.kind == "Job":
                    self.lines.append(
                        f"  image {desired.kind}/{desired.workload} {desired.container}: "
                        "ABSENT (completed or hook-deleted Job)"
                    )
                    continue
                self.lines.append(
                    f"  image {desired.kind}/{desired.workload} {desired.container}: MISSING WORKLOAD"
                )
                self._block(
                    f"desired workload is missing: {namespace}/{desired.kind}/{desired.workload}"
                )
                continue
            pod_spec = _pod_spec(live) or {}
            live_image = _container_map(pod_spec, desired.container_type).get(desired.container)
            if live_image == desired.image:
                status = "MATCH"
            elif live_image is None:
                status = "MISSING CONTAINER"
                self._block(
                    f"live container is missing: {desired.kind}/{desired.workload}/{desired.container}"
                )
            else:
                status = "DRIFT"
                self._block(
                    f"image drift: {desired.kind}/{desired.workload}/{desired.container} "
                    f"desired {desired.image}, live {live_image}"
                )
            self.lines.append(
                f"  image {desired.kind}/{desired.workload} {desired.container}: "
                f"{status} desired={desired.image} live={live_image or '<missing>'}"
            )

        self.lines.extend(("", "LIVE POD IMAGES AND RUNTIME IDS"))
        pods_result = self._kubectl(
            context, "--namespace", namespace, "get", "pods", "-o", "json"
        )
        pods_document = self._json_result(pods_result, "Kubernetes pods")
        if pods_document is None:
            self.lines.append(f"  UNKNOWN: {_short_error(pods_result)}")
            return
        contracts_by_repository = {contract.repository: contract for contract in contracts}
        for pod in sorted(
            (item for item in _list(pods_document.get("items")) if isinstance(item, Mapping)),
            key=lambda item: str(_mapping(item.get("metadata")).get("name")),
        ):
            pod_name = str(_mapping(pod.get("metadata")).get("name", "<unnamed>"))
            health, detail = _pod_health(pod)
            self.lines.append(f"  Pod/{pod_name}: {health} ({detail})")
            if health == "UNHEALTHY":
                self._block(f"pod is unhealthy: {namespace}/{pod_name}")
            spec = _mapping(pod.get("spec"))
            status = _mapping(pod.get("status"))
            for field, status_field, container_type in (
                ("initContainers", "initContainerStatuses", "init"),
                ("containers", "containerStatuses", "regular"),
            ):
                statuses = {
                    str(item.get("name")): item
                    for item in _list(status.get(status_field))
                    if isinstance(item, Mapping)
                }
                for container in _list(spec.get(field)):
                    if not isinstance(container, Mapping):
                        continue
                    name = str(container.get("name", "<unnamed>"))
                    reference = str(container.get("image", "<missing>"))
                    runtime_id = str(_mapping(statuses.get(name)).get("imageID", "UNKNOWN"))
                    self.lines.append(
                        f"    {container_type}/{name}: live={reference} imageID={runtime_id}"
                    )
                    contract = contracts_by_repository.get(_image_repository(reference))
                    if contract is None:
                        continue
                    if reference != contract.reference:
                        self._block(
                            f"pod image drift: {pod_name}/{name} desired {contract.reference}, "
                            f"live {reference}"
                        )
                    runtime_digest = _runtime_manifest_digest(runtime_id)
                    if runtime_digest is not None and runtime_digest != contract.digest:
                        self._block(
                            f"runtime image drift: {pod_name}/{name} desired {contract.digest}, "
                            f"runtime {runtime_digest}"
                        )

    def _report_events(self, context: str, namespace: str) -> None:
        self.lines.extend(("", "RECENT WARNING EVENTS"))
        if not self.cluster_available:
            self.lines.append("  UNKNOWN: Kubernetes context or API is unavailable")
            return
        result = self._kubectl(
            context,
            "--namespace",
            namespace,
            "get",
            "events",
            "--field-selector",
            "type=Warning",
            "--sort-by=.lastTimestamp",
            "-o",
            "json",
        )
        document = self._json_result(result, "Kubernetes warning events")
        if document is None:
            self.lines.append(f"  UNKNOWN: {_short_error(result)}")
            return
        events = [item for item in _list(document.get("items")) if isinstance(item, Mapping)][-20:]
        if not events:
            self.lines.append("  <none>")
            return
        for event in events:
            metadata = _mapping(event.get("metadata"))
            involved = _mapping(event.get("involvedObject"))
            timestamp = (
                event.get("eventTime")
                or event.get("lastTimestamp")
                or metadata.get("creationTimestamp")
                or "UNKNOWN"
            )
            message = " ".join(str(event.get("message", "")).split())[:240]
            self.lines.append(
                f"  {timestamp} {involved.get('kind', 'Object')}/{involved.get('name', 'UNKNOWN')} "
                f"{event.get('reason', 'Warning')}: {message}"
            )

    def run(self) -> tuple[int, str]:
        try:
            contracts = load_image_contracts(self.repository_root, self.environment)
        except ImageContractError as error:
            contracts = ()
            self._block(f"image contract is invalid: {error}")
        namespace = self._namespace()
        context, context_source = self._resolve_context()
        self.lines.extend(
            (
                "STACK RECOVERY REPORT (READ ONLY)",
                f"Environment:        {self.environment}",
                f"Kubernetes context: {context} ({context_source})",
                f"Namespace:          {namespace}",
                "Mutation policy:     no Git, registry, Argo CD, or Kubernetes writes",
            )
        )
        rendered, git_head = self._render()
        desired_images = inventory_images(rendered, namespace)
        required_secrets = inventory_required_secrets(rendered)
        required_config_maps = inventory_required_config_maps(rendered)

        platform_contract: PlatformInputContract | None = None
        if self.environment == "prod":
            try:
                platform_contract = load_platform_input_contract(self.repository_root)
            except PlatformInputContractError as error:
                self._block(f"platform input contract is invalid: {error}")

        self._report_argo(context, git_head)
        self._report_registry(contracts)
        if platform_contract is not None:
            self._report_platform_contract(context, platform_contract)
        else:
            self._report_config_maps(context, namespace, required_config_maps)
            self._report_secrets(context, namespace, required_secrets)
        self._report_desired_images(desired_images)
        self._report_live_state(context, namespace, desired_images, contracts)
        self._report_events(context, namespace)

        self.lines.extend(("", "BLOCKER SUMMARY"))
        if self.blockers:
            for blocker in self.blockers:
                self.lines.append(f"  - {blocker}")
            self.lines.append(f"RESULT: UNHEALTHY ({len(self.blockers)} blockers)")
            return 1, "\n".join(self.lines) + "\n"
        self.lines.append("  NONE")
        self.lines.append("RESULT: HEALTHY")
        return 0, "\n".join(self.lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=ENVIRONMENTS, default="prod")
    parser.add_argument("--kube-context", default="")
    parser.add_argument("--kustomize", default="kubectl")
    parser.add_argument("--registry-plain-http", choices=("0", "1"), default="0")
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    reporter = RecoveryReporter(
        arguments.repository_root,
        arguments.environment,
        arguments.kube_context,
        arguments.kustomize,
        arguments.registry_plain_http == "1",
    )
    returncode, report = reporter.run()
    sys.stdout.write(report)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
