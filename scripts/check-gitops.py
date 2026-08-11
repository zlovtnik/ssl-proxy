#!/usr/bin/env python3
"""Validate the canonical Kustomize and Argo CD delivery surfaces."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml


Document = dict[str, Any]
Documents = list[Document]

CANONICAL_KUSTOMIZATIONS = (
    "cyber-stack/argocd",
    "cyber-stack/matrix/dev",
    "cyber-stack/matrix/dev/bootstrap",
    "cyber-stack/matrix/dev/data-plane",
    "cyber-stack/matrix/dev/app-stack",
    "cyber-stack/matrix/prod",
    "cyber-stack/matrix/prod/bootstrap",
    "cyber-stack/matrix/prod/data-plane",
    "cyber-stack/matrix/prod/app-stack",
)

WORKLOAD_APPLICATIONS = {
    "ssl-proxy-prod-bootstrap": {
        "path": "cyber-stack/matrix/prod/bootstrap",
        "namespace": "prod-ssl-proxy",
        "component": "bootstrap",
        "environment": "prod",
    },
    "ssl-proxy-prod-data-plane": {
        "path": "cyber-stack/matrix/prod/data-plane",
        "namespace": "prod-ssl-proxy",
        "component": "data-plane",
        "environment": "prod",
        "ignore_pvc": True,
    },
    "ssl-proxy-prod-app-stack": {
        "path": "cyber-stack/matrix/prod/app-stack",
        "namespace": "prod-ssl-proxy",
        "component": "app-stack",
        "environment": "prod",
    },
}

FIRST_PARTY_IMAGES = (
    "ssl-proxy",
    "java-coordinator",
    "atheros-sensor",
    "atheros-search",
    "atheros-search-ui",
    "schema-migrator-backend",
    "schema-migrator-ui",
    "tidb-runtime-schema",
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _path(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _metadata(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(document.get("metadata"))


def _kind_name(document: Mapping[str, Any], kind: str, name: str) -> bool:
    return document.get("kind") == kind and _metadata(document).get("name") == name


def _find(documents: Iterable[Document], kind: str, name: str) -> list[Document]:
    return [document for document in documents if _kind_name(document, kind, name)]


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _load_documents(text: str, relative: str, errors: list[str]) -> Documents | None:
    try:
        values = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        errors.append(f"{relative}: invalid YAML: {exc}")
        return None
    documents: Documents = []
    for index, value in enumerate(values, start=1):
        if value is None:
            continue
        if not isinstance(value, dict):
            errors.append(f"{relative}: YAML document {index} must be a mapping")
            return None
        documents.append(value)
    return documents


def _documents(value: Documents | str) -> Documents:
    """Accept parsed documents in production and YAML strings in focused tests."""
    if not isinstance(value, str):
        return value
    errors: list[str] = []
    return _load_documents(value, "rendered output", errors) or []


def _pod_containers(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        _mapping(container)
        for container in _list(_path(document, "spec", "template", "spec", "containers"))
        if isinstance(container, Mapping)
    ]


def _environment(containers: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        _mapping(entry)
        for container in containers
        for entry in _list(container.get("env"))
        if isinstance(entry, Mapping)
    ]


def _parse_bytes(value: str, unit: str = "") -> int:
    multipliers = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    return int(value) * multipliers.get(unit.upper().rstrip("I"), 1)


def _quantity_bytes(value: Any) -> int | None:
    match = re.fullmatch(r"(\d+)([KMGT]i?)?", str(value))
    if match is None:
        return None
    return _parse_bytes(match.group(1), match.group(2) or "")


def _check_otel_endpoint(rendered: Documents | str, relative: str) -> list[str]:
    if any("ssl-proxy-otel-collector" in value for value in _strings(_documents(rendered))):
        return [
            f"{relative}: rendered output contains nonexistent "
            "ssl-proxy-otel-collector service reference"
        ]
    return []


def _check_redpanda_memory(rendered: Documents | str, relative: str) -> list[str]:
    statefulsets = _find(_documents(rendered), "StatefulSet", "ssl-proxy-redpanda")
    if not statefulsets:
        return []
    for container in _pod_containers(statefulsets[0]):
        args = [str(argument) for argument in _list(container.get("args"))]
        heap: str | None = None
        for index, argument in enumerate(args):
            if argument == "--memory" and index + 1 < len(args):
                heap = args[index + 1]
            elif argument.startswith("--memory="):
                heap = argument.removeprefix("--memory=")
        limit = _path(container, "resources", "limits", "memory")
        heap_bytes = _quantity_bytes(heap) if heap is not None else None
        limit_bytes = _quantity_bytes(limit) if limit is not None else None
        if heap_bytes is None or limit_bytes is None:
            continue
        headroom = limit_bytes - heap_bytes
        if headroom < 512 * 1024**2:
            return [
                f"{relative}: Redpanda memory limit must provide at least "
                f"512 MiB headroom over --memory (got {headroom // 1024**2} MiB)"
            ]
    return []


def _check_proxy_probes(rendered: Documents | str, relative: str) -> list[str]:
    deployments = _find(_documents(rendered), "Deployment", "ssl-proxy-proxy")
    if not deployments:
        return []
    errors: list[str] = []
    for container in _pod_containers(deployments[0]):
        for probe in ("livenessProbe", "readinessProbe"):
            if "httpGet" in _mapping(container.get(probe)):
                errors.append(
                    f"{relative}: proxy {probe} must use exec probe "
                    "on loopback, not httpGet"
                )
    return errors


def _check_proxy_wireguard_route(rendered: Documents | str, relative: str) -> list[str]:
    deployments = _find(_documents(rendered), "Deployment", "ssl-proxy-proxy")
    if not deployments:
        return []
    for container in _pod_containers(deployments[0]):
        for port in _list(container.get("ports")):
            definition = _mapping(port)
            if definition.get("containerPort") != 443:
                continue
            if definition.get("hostPort") == 443 and definition.get("protocol") == "UDP":
                return []
    return [f"{relative}: proxy WireGuard UDP/443 has no external hostPort route"]


def _check_jaeger_probes(rendered: Documents | str, relative: str) -> list[str]:
    deployments = _find(
        _documents(rendered), "Deployment", "ssl-proxy-telemetry-jaeger"
    )
    if not deployments:
        return []
    containers = [
        container
        for container in _pod_containers(deployments[0])
        if container.get("name") == "jaeger"
    ]
    if len(containers) != 1:
        return [f"{relative}: expected one Jaeger container"]
    container = containers[0]
    ports = {
        _mapping(port).get("name"): _mapping(port).get("containerPort")
        for port in _list(container.get("ports"))
    }
    errors: list[str] = []
    if ports.get("admin") != 14269:
        errors.append(f"{relative}: Jaeger admin port must be named admin on 14269")
    for probe_name in ("startupProbe", "livenessProbe", "readinessProbe"):
        probe = _mapping(container.get(probe_name))
        http_get = _mapping(probe.get("httpGet"))
        if http_get.get("path") != "/" or http_get.get("port") != "admin":
            errors.append(
                f"{relative}: Jaeger {probe_name} must use the admin health endpoint"
            )
    startup = _mapping(container.get("startupProbe"))
    try:
        startup_budget = int(startup.get("failureThreshold", 0)) * int(
            startup.get("periodSeconds", 0)
        )
    except (TypeError, ValueError):
        startup_budget = 0
    if startup_budget < 600:
        errors.append(
            f"{relative}: Jaeger startup probe must allow at least 600 seconds"
        )
    return errors


def _check_atheros_search_auth(rendered: Documents | str, relative: str) -> list[str]:
    deployments = _find(_documents(rendered), "Deployment", "ssl-proxy-atheros-search")
    if not deployments:
        return []
    if any(entry.get("name") == "ATHSEARCH_API_TOKEN_SHA256" for entry in _environment(_pod_containers(deployments[0]))):
        return [
            f"{relative}: browser-facing Atheros Search enables bearer auth "
            "without a browser or trusted-proxy credential flow"
        ]
    return []


def _check_atheros_search_ui_proxy(rendered: Documents | str, relative: str) -> list[str]:
    config_maps = [
        document
        for document in _documents(rendered)
        if document.get("kind") == "ConfigMap"
        and str(_metadata(document).get("name", "")).startswith("ssl-proxy-atheros-search-ui-nginx")
    ]
    if not config_maps:
        return []
    configuration = "\n".join(
        str(value) for document in config_maps for value in _mapping(document.get("data")).values()
    )
    errors: list[str] = []
    for dynamic_proxy in ("proxy_pass $search_backend;", "proxy_pass $readyz_backend/readyz;"):
        if dynamic_proxy in configuration:
            errors.append(
                f"{relative}: Atheros Search UI proxy must not use "
                f"dynamic upstream {dynamic_proxy!r}"
            )
    for static_proxy in (
        "proxy_pass http://ssl-proxy-atheros-search:8080;",
        "proxy_pass http://ssl-proxy-atheros-search:8080/readyz;",
    ):
        if static_proxy not in configuration:
            errors.append(
                f"{relative}: Atheros Search UI proxy is missing "
                f"static upstream {static_proxy!r}"
            )
    return errors


def _check_keycloak_database_credential(rendered: Documents | str, relative: str) -> list[str]:
    deployments = _find(_documents(rendered), "Deployment", "ssl-proxy-schema-migrator-keycloak")
    if not deployments:
        return []
    passwords = [entry for entry in _environment(_pod_containers(deployments[0])) if entry.get("name") == "KC_DB_PASSWORD"]
    secret = _mapping(_path(passwords[0], "valueFrom", "secretKeyRef")) if passwords else {}
    if secret.get("name") != "tidb-keycloak" or secret.get("key") != "password":
        return [
            f"{relative}: Keycloak database password must come from "
            "tidb-keycloak/password"
        ]
    return []


def _topic_replication(documents: Documents) -> list[int]:
    values: list[int] = []
    for document in documents:
        if document.get("kind") != "ConfigMap":
            continue
        for key, content in _mapping(document.get("data")).items():
            if key != "topics.manifest":
                continue
            for line in str(content).splitlines():
                fields = line.strip().split("|")
                if len(fields) >= 3 and fields[0] and not fields[0].startswith("#"):
                    try:
                        values.append(int(fields[2]))
                    except ValueError:
                        pass
    for document in documents:
        for entry in _environment(_pod_containers(document)):
            if entry.get("name") == "SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR":
                try:
                    values.append(int(str(entry.get("value"))))
                except (TypeError, ValueError):
                    pass
    return values


def _check_redpanda_topic_replication(rendered: Documents | str, relative: str) -> list[str]:
    documents = _documents(rendered)
    brokers = _find(documents, "StatefulSet", "ssl-proxy-redpanda")
    requested_replication = _topic_replication(documents)
    if not brokers or not requested_replication:
        return []
    try:
        broker_count = int(_path(brokers[0], "spec", "replicas"))
    except (TypeError, ValueError):
        return []
    maximum = max(requested_replication)
    if maximum > broker_count:
        return [
            f"{relative}: topic replication factor {maximum} "
            f"exceeds Redpanda broker count {broker_count}"
        ]
    return []


def _check_environment_identity_hostnames(rendered: Mapping[str, Documents | str]) -> list[str]:
    hostnames: dict[str, str] = {}
    errors: list[str] = []
    for environment in ("dev", "prod"):
        relative = f"cyber-stack/matrix/{environment}/bootstrap"
        config_maps = [
            document
            for document in _documents(rendered.get(relative, []))
            if document.get("kind") == "ConfigMap"
            and "IDENTITY_HOSTNAME" in _mapping(document.get("data"))
        ]
        if not config_maps:
            errors.append(f"{relative}: environment identity hostname is missing")
            continue
        hostname = str(_mapping(config_maps[0].get("data")).get("IDENTITY_HOSTNAME"))
        hostnames[environment] = hostname
        if ".example." in hostname or hostname.endswith(".example"):
            errors.append(f"{relative}: example identity hostname is not deployable")
    if len(hostnames) == 2 and hostnames["dev"] == hostnames["prod"]:
        errors.append("dev and prod must not share an identity hostname")
    return errors


def _check_traefik_redirect(rendered: Documents | str, relative: str) -> list[str]:
    if any("entrypoints.web.http.redirections.entrypoint.port" in value for value in _strings(_documents(rendered))):
        return [f"{relative}: Traefik entrypoint.port is not a supported redirection field"]
    return []


def _wave(document: Mapping[str, Any]) -> int | None:
    value = _mapping(_metadata(document).get("annotations")).get("argocd.argoproj.io/sync-wave")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _check_tidb_waves(rendered: Documents | str, relative: str) -> list[str]:
    documents = _documents(rendered)
    jobs = {name: _find(documents, "Job", name) for name in ("ssl-proxy-tidb-init", "ssl-proxy-tidb-schema-executor", "ssl-proxy-tidb-init-grants")}
    if any(not values for values in jobs.values()):
        return []
    waves = {name: max(wave for document in values if (wave := _wave(document)) is not None) for name, values in jobs.items() if any(_wave(document) is not None for document in values)}
    if len(waves) != len(jobs):
        return []
    init_wave = waves["ssl-proxy-tidb-init"]
    schema_wave = waves["ssl-proxy-tidb-schema-executor"]
    grants_wave = waves["ssl-proxy-tidb-init-grants"]
    errors: list[str] = []
    if init_wave >= schema_wave:
        errors.append(f"{relative}: TiDB init wave ({init_wave}) must be less than schema executor wave ({schema_wave})")
    if schema_wave >= grants_wave:
        errors.append(f"{relative}: schema executor wave ({schema_wave}) must be less than grants wave ({grants_wave})")
    return errors


def _schema_migrator_contract_marker(root: Path, errors: list[str]) -> str | None:
    relative = "sql/tidb/schema_migrator/manifest.yaml"
    text = _read_required(root, relative, errors, "manifest")
    if text is None:
        return None
    documents = _load_documents(text, relative, errors)
    if not documents:
        return None
    manifest = documents[0]
    version = manifest.get("schema_version")
    checksum = manifest.get("manifest_sha256")
    if version is None or not re.fullmatch(r"[0-9a-f]{64}", str(checksum)):
        errors.append(f"{relative}: missing schema contract version or checksum")
        return None
    version_text = f"{version:03d}" if isinstance(version, int) else str(version)
    return f"schema-migrator-{version_text}-{checksum}"


def _check_schema_executor_contract(rendered: Documents | str, relative: str, expected_marker: str) -> list[str]:
    jobs = _find(_documents(rendered), "Job", "ssl-proxy-tidb-schema-executor")
    if len(jobs) != 1:
        return [f"{relative}: expected one rendered TiDB schema executor Job"]
    job = jobs[0]
    errors: list[str] = []
    marker = _path(job, "spec", "template", "metadata", "annotations", "ssl-proxy.io/content-hash")
    if marker != expected_marker:
        errors.append(f"{relative}: schema executor content-hash must equal canonical contract {expected_marker}")
    images = [str(container.get("image", "")) for container in _pod_containers(job)]
    if not any(re.search(r"tidb-runtime-schema@sha256:[0-9a-f]{64}$", image) for image in images):
        errors.append(f"{relative}: schema executor must use a digest-pinned image")
    return errors


def render(root: Path, executable: str, relative: str) -> tuple[str, str | None]:
    command = [executable, "kustomize", str(root / relative)] if Path(executable).name == "kubectl" else [executable, "build", str(root / relative)]
    command.extend(["--load-restrictor", "LoadRestrictionsNone"])
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return "", f"{relative}: Kustomize render failed: {detail}"
    return result.stdout, None


def _read_required(root: Path, relative: Path | str, errors: list[str], description: str) -> str | None:
    relative_path = Path(relative)
    path = root / relative_path
    if not path.is_file():
        errors.append(f"{relative_path}: required {description} is missing")
        return None
    return path.read_text(encoding="utf-8")


def _read_yaml_required(root: Path, relative: Path | str, errors: list[str], description: str) -> Documents | None:
    text = _read_required(root, relative, errors, description)
    return _load_documents(text, str(relative), errors) if text is not None else None


def _image_pin_counts(value: Documents | str) -> tuple[int, int]:
    documents = _documents(value)
    kustomizations = [document for document in documents if document.get("kind") == "Kustomization"]
    if not kustomizations:
        return 0, 0
    images = _list(kustomizations[0].get("images"))
    entries = [entry for entry in images if isinstance(entry, Mapping)]
    return len(entries), sum(1 for entry in entries if str(entry.get("digest", "")).startswith("sha256:"))


def _rendered_images(documents: Documents) -> Iterable[str]:
    for document in documents:
        for container in _pod_containers(document):
            image = container.get("image")
            if image is not None:
                yield str(image)


def _replace_templates(value: Any, parameters: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        return re.sub(r"{{\s*\.?([A-Za-z0-9_-]+)\s*}}", lambda match: str(parameters.get(match.group(1), match.group(0))), value)
    if isinstance(value, list):
        return [_replace_templates(child, parameters) for child in value]
    if isinstance(value, Mapping):
        return {key: _replace_templates(child, parameters) for key, child in value.items()}
    return value


def _merge_mapping(destination: dict[str, Any], patch: Mapping[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(destination.get(key), dict):
            _merge_mapping(destination[key], value)
        else:
            destination[key] = value


def _template_patch(application_set: Mapping[str, Any], parameters: Mapping[str, Any]) -> Mapping[str, Any]:
    """Evaluate the list-generator's small, documented data-plane patch surface."""
    patch = application_set.get("spec", {}).get("templatePatch")
    if not isinstance(patch, str):
        return {}
    conditional = re.search(r'{{-?\s*if\s+eq\s+\.component\s+"([^"]+)"\s*}}(?P<body>.*?){{-?\s*end\s*}}', patch, re.DOTALL)
    if conditional is not None:
        if parameters.get("component") != conditional.group(1):
            return {}
        patch = conditional.group("body")
    errors: list[str] = []
    documents = _load_documents(_replace_templates(patch, parameters), "ApplicationSet templatePatch", errors)
    return documents[0] if documents and not errors else {}


def _applications_from_set(application_set: Document) -> Documents:
    template = _mapping(_path(application_set, "spec", "template"))
    applications: Documents = []
    for generator in _list(_path(application_set, "spec", "generators")):
        for element in _list(_path(_mapping(generator), "list", "elements")):
            if isinstance(element, Mapping):
                rendered = _replace_templates(template, element)
                if isinstance(rendered, dict):
                    _merge_mapping(rendered, _template_patch(application_set, element))
                    applications.append(rendered)
    return applications


def _validate_workload_application(application: Mapping[str, Any], relative: str, expected: Mapping[str, Any], errors: list[str]) -> None:
    source = _mapping(_path(application, "spec", "source"))
    destination = _mapping(_path(application, "spec", "destination"))
    automated = _mapping(_path(application, "spec", "syncPolicy", "automated"))
    required = {
        "targetRevision: main": source.get("targetRevision") == "main",
        f"path: {expected['path']}": source.get("path") == expected["path"],
        "automated:": bool(automated),
        "prune: true": automated.get("prune") is True,
        "selfHeal: true": automated.get("selfHeal") is True,
        "allowEmpty: false": automated.get("allowEmpty") is False,
    }
    for message, valid in required.items():
        if not valid:
            errors.append(f"{relative}: missing {message!r}")
    if "kustomize" not in source:
        errors.append(f"{relative}: source must select the Kustomize renderer")
    if "directory" in source:
        errors.append(f"{relative}: plain-directory renderer is not allowed")
    if any(str(option) == "CreateNamespace=true" for option in _list(_path(application, "spec", "syncPolicy", "syncOptions"))):
        errors.append(f"{relative}: namespace creation must come from Git")
    if destination.get("namespace") != expected["namespace"]:
        errors.append(f"{relative}: destination namespace must be {expected['namespace']}")
    if application.get("spec", {}).get("project") != "ssl-proxy":
        errors.append(f"{relative}: Application project must be ssl-proxy")
    if source.get("repoURL") != "https://github.com/zlovtnik/ssl-proxy.git":
        errors.append(f"{relative}: Application source repository is not preserved")
    if destination.get("server") != "https://kubernetes.default.svc":
        errors.append(f"{relative}: Application destination server is not preserved")
    sync_options = {str(option) for option in _list(_path(application, "spec", "syncPolicy", "syncOptions"))}
    required_options = {"PrunePropagationPolicy=foreground", "ApplyOutOfSyncOnly=true", "ServerSideApply=true"}
    if not required_options.issubset(sync_options):
        errors.append(f"{relative}: Application sync options are not preserved")
    labels = _mapping(_metadata(application).get("labels"))
    if labels.get("app.kubernetes.io/component") != expected["component"] or labels.get("environment") != expected["environment"]:
        errors.append(f"{relative}: Application labels do not match {expected['environment']}/{expected['component']}")
    pvc_ignore = any(
        _mapping(rule).get("group") == "apps"
        and _mapping(rule).get("kind") == "StatefulSet"
        and "/spec/volumeClaimTemplates" in _list(_mapping(rule).get("jsonPointers"))
        for rule in _list(_path(application, "spec", "ignoreDifferences"))
    )
    if expected.get("ignore_pvc") and not pvc_ignore:
        errors.append(f"{relative}: data-plane PVC ignore rule is not preserved")


def _check_application_set(documents: Documents, errors: list[str]) -> None:
    relative = "cyber-stack/argocd"
    application_sets = [document for document in documents if document.get("kind") == "ApplicationSet"]
    if len(application_sets) != 1:
        errors.append(f"{relative}: expected one workload ApplicationSet")
        return
    applications = _applications_from_set(application_sets[0])
    generated_names = {
        str(_metadata(application).get("name")) for application in applications
    }
    unexpected = sorted(generated_names - set(WORKLOAD_APPLICATIONS))
    if unexpected:
        errors.append(
            f"{relative}: production ApplicationSet generates unexpected Applications: "
            + ", ".join(unexpected)
        )
    for name, expected in WORKLOAD_APPLICATIONS.items():
        matching = [application for application in applications if _metadata(application).get("name") == name]
        if len(matching) != 1:
            errors.append(f"{relative}: ApplicationSet must generate Application {name} exactly once")
            continue
        _validate_workload_application(matching[0], relative, expected, errors)
    workload_names = set(WORKLOAD_APPLICATIONS)
    direct = [document for document in documents if document.get("kind") == "Application" and _metadata(document).get("name") in workload_names]
    if direct:
        errors.append(f"{relative}: workload Applications must be generated by the ApplicationSet")


def _check_prod_project(documents: Documents, errors: list[str]) -> None:
    relative = "cyber-stack/argocd"
    projects = _find(documents, "AppProject", "ssl-proxy")
    if len(projects) != 1:
        errors.append(f"{relative}: expected one ssl-proxy AppProject")
        return
    destinations = _list(_path(projects[0], "spec", "destinations"))
    expected = {
        ("prod-ssl-proxy", "https://kubernetes.default.svc"),
    }
    actual = {
        (str(_mapping(destination).get("namespace")), str(_mapping(destination).get("server")))
        for destination in destinations
    }
    if actual != expected:
        errors.append(
            f"{relative}: ssl-proxy AppProject destinations must be production-only"
        )
    forbidden_kinds = {"ImageUpdater"}
    forbidden_applications = {"ssl-proxy-image-updater"}
    if any(document.get("kind") in forbidden_kinds for document in documents):
        errors.append(f"{relative}: production control plane must not install Image Updater")
    if any(
        document.get("kind") == "Application"
        and _metadata(document).get("name") in forbidden_applications
        for document in documents
    ):
        errors.append(f"{relative}: production control plane must not install dev controllers")


def check_repository(root: Path, executable: str) -> list[str]:
    errors: list[str] = []
    rendered_kustomizations: dict[str, Documents] = {}
    expected_schema_marker = _schema_migrator_contract_marker(root, errors)

    for relative in CANONICAL_KUSTOMIZATIONS:
        path = root / relative
        if not path.exists():
            errors.append(f"{relative}: required kustomization not found")
            continue
        rendered, error = render(root, executable, relative)
        if error:
            errors.append(error)
            continue
        documents = _load_documents(rendered, relative, errors)
        if documents is None:
            continue
        rendered_kustomizations[relative] = documents
        if any(image.endswith(":latest") for image in _rendered_images(documents)):
            errors.append(f"{relative}: rendered workload uses a mutable latest tag")
        for image in FIRST_PARTY_IMAGES:
            if any(rendered_image == image or rendered_image.startswith(f"{image}:") for rendered_image in _rendered_images(documents)):
                errors.append(f"{relative}: rendered workload retains logical image name {image}")
        for check in (_check_otel_endpoint, _check_redpanda_memory, _check_proxy_probes, _check_proxy_wireguard_route, _check_jaeger_probes, _check_atheros_search_auth, _check_atheros_search_ui_proxy, _check_keycloak_database_credential, _check_redpanda_topic_replication, _check_traefik_redirect, _check_tidb_waves):
            errors.extend(check(documents, relative))

    errors.extend(_check_environment_identity_hostnames(rendered_kustomizations))
    if expected_schema_marker is not None:
        for environment in ("dev", "prod"):
            relative = f"cyber-stack/matrix/{environment}/data-plane"
            if relative in rendered_kustomizations:
                errors.extend(_check_schema_executor_contract(rendered_kustomizations[relative], relative, expected_schema_marker))
    prod_documents = [document for component in ("bootstrap", "data-plane", "app-stack") for document in rendered_kustomizations.get(f"cyber-stack/matrix/prod/{component}", [])]
    errors.extend(_check_redpanda_topic_replication(prod_documents, "cyber-stack/matrix/prod"))
    if "cyber-stack/argocd" in rendered_kustomizations:
        _check_application_set(rendered_kustomizations["cyber-stack/argocd"], errors)
        _check_prod_project(rendered_kustomizations["cyber-stack/argocd"], errors)

    for environment in ("dev", "prod"):
        for component in ("data-plane", "app-stack"):
            relative = Path("cyber-stack/matrix") / environment / component / "kustomization.yaml"
            documents = _read_yaml_required(root, relative, errors, "component kustomization")
            if documents is None:
                continue
            kustomizations = [document for document in documents if document.get("kind") == "Kustomization"]
            if len(kustomizations) != 1:
                errors.append(f"{relative}: required component Kustomization is missing")
                continue
            images = _list(kustomizations[0].get("images"))
            if any("newTag" in _mapping(image) for image in images):
                errors.append(f"{relative}: first-party images must be digest pinned")
            image_entries, digest_entries = _image_pin_counts(documents)
            if image_entries != digest_entries:
                errors.append(f"{relative}: expected one digest for each of {image_entries} image entries, found {digest_entries}")

    for environment in ("dev", "prod"):
        relative = Path("cyber-stack/matrix") / environment / "namespace.yaml"
        documents = _read_yaml_required(root, relative, errors, "Namespace manifest")
        if documents is None:
            continue
        namespaces = [document for document in documents if document.get("kind") == "Namespace"]
        annotations = _mapping(_metadata(namespaces[0]).get("annotations")) if namespaces else {}
        if "Prune=false" not in str(annotations.get("argocd.argoproj.io/sync-options", "")):
            errors.append(f"{relative}: namespace prune must be disabled")

    makefile = (root / "Makefile").read_text(encoding="utf-8")
    for forbidden in ("argocd-update", "release-all", "kubectl patch application"):
        if forbidden in makefile:
            errors.append(f"Makefile: live-cluster promotion surface remains: {forbidden}")
    for target in ("test", "lint", "dependency-boundaries", "atheros-search-test"):
        if re.search(rf"(?m)^{re.escape(target)}:\s*$", makefile) is None:
            errors.append(f"Makefile: documented verification target is missing: {target}")

    stack_relative = "stackctl/stack.yaml"
    stack_documents = _read_yaml_required(root, stack_relative, errors, "stack configuration")
    if stack_documents:
        for component in _mapping(stack_documents[0].get("components")).values():
            chart = _mapping(component).get("chart")
            if chart is None:
                continue
            overlay = (root / str(chart).removeprefix("./")).resolve()
            if not (overlay / "kustomization.yaml").is_file():
                errors.append("stackctl/stack.yaml: component overlay is not a Kustomization: " + str(chart))

    deploy_source = (root / "ops/src/sslproxy_ops/stack/deploy.py").read_text(encoding="utf-8")
    if "kustomize_apply" in deploy_source:
        errors.append("stackctl: direct Kustomize cluster apply path remains")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent, help="repository root")
    parser.add_argument("--kustomize", default=None)
    args = parser.parse_args()
    executable = args.kustomize or shutil.which("kustomize")
    if not executable:
        print("gitops-check: kustomize executable was not found", file=sys.stderr)
        return 1
    errors = check_repository(args.root.resolve(), executable)
    if errors:
        for error in errors:
            print(f"gitops-check: {error}", file=sys.stderr)
        return 1
    print("gitops-check: canonical Kustomize and Argo CD surfaces are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
