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

SCRIPTS_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPTS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIRECTORY))

from platform_input_contract import (  # noqa: E402
    PlatformInputContractError,
    compare_contract_to_rendered,
    find_committed_secret_values,
    load_platform_input_contract,
)


Document = dict[str, Any]
Documents = list[Document]

CANONICAL_KUSTOMIZATIONS = (
    "cyber-stack/argocd-bootstrap",
    "cyber-stack/argocd",
    "cyber-stack/matrix/prod",
    "cyber-stack/matrix/prod/bootstrap",
    "cyber-stack/matrix/prod/data-plane",
    "cyber-stack/matrix/prod/app-stack",
)

PLATFORM_BOOTSTRAP_APPLICATION = "ssl-proxy-platform-bootstrap"

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
    "postgres-runtime-schema",
)

JAEGER_V2_IMAGE = (
    "jaegertracing/jaeger:2.20.0@"
    "sha256:46a886260e04002d8f45e213fc39063fa11a50446048fdaa64786fc0840cb9f8"
)

PHASE_ONE_ROUTE_KINDS = {
    "Gateway",
    "GRPCRoute",
    "HTTPRoute",
    "Ingress",
    "IngressRoute",
    "Middleware",
    "TCPRoute",
    "TLSRoute",
    "UDPRoute",
}

PHASE_ONE_ROUTE_ALLOWLIST = {
    ("Ingress", "ssl-proxy-telemetry-grafana"),
}

PHASE_ONE_HOST_NETWORK_ALLOWLIST = {
    ("DaemonSet", "ssl-proxy-atheros-sensor"),
    ("Deployment", "ssl-proxy-telemetry-postgres-metrics-bridge"),
}

OBSERVABILITY_CATALOG_SERVICES = {
    "ssl-proxy",
    "octopus",
    "atheros-search",
    "atheros-search-ui",
    "schema-migrator-backend",
    "schema-migrator-ui",
    "keycloak",
    "schema-migrator-traefik",
    "redpanda",
    "redis",
    "minio",
    "prometheus",
    "alertmanager",
    "grafana",
    "loki",
    "alloy",
    "otel-collector",
    "jaeger",
    "pushgateway",
    "kube-state-metrics",
    "blackbox-exporter",
    "node-exporter",
    "cadvisor",
    "jenkins",
    "registry",
}

STANDARD_LABEL_KEYS = (
    "app.kubernetes.io/name",
    "app.kubernetes.io/component",
    "app.kubernetes.io/managed-by",
)

STANDARD_LABELED_KINDS = {
    "ConfigMap",
    "DaemonSet",
    "Deployment",
    "Job",
    "NetworkPolicy",
    "PersistentVolumeClaim",
    "Role",
    "RoleBinding",
    "Service",
    "ServiceAccount",
    "StatefulSet",
}


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


def _quantity_millicores(value: Any) -> int | None:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(m)?", str(value))
    if match is None:
        return None
    quantity = float(match.group(1))
    return int(quantity if match.group(2) else quantity * 1000)


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
        proxy_required = relative in {
            "cyber-stack/base",
            "cyber-stack/base/proxy",
            "cyber-stack/matrix/dev",
            "cyber-stack/matrix/dev/app-stack",
            "cyber-stack/matrix/prod",
            "cyber-stack/matrix/prod/app-stack",
        }
        return (
            [f"{relative}: expected one ssl-proxy-proxy Deployment"]
            if proxy_required
            else []
        )
    for container in _pod_containers(deployments[0]):
        if container.get("name") != "ssl-proxy":
            continue
        errors: list[str] = []
        expected = {"livenessProbe": "/health", "readinessProbe": "/ready"}
        for probe, path in expected.items():
            http_get = _mapping(_path(container, probe, "httpGet"))
            if http_get.get("path") != path or http_get.get("port") != "observability":
                errors.append(
                    f"{relative}: proxy {probe} must use {path} on the "
                    "dedicated observability port"
                )
        admin = [
            entry for entry in _list(container.get("env"))
            if _mapping(entry).get("name") == "ADMIN_BIND_ADDR"
        ]
        if len(admin) != 1 or _mapping(admin[0]).get("value") != "127.0.0.1":
            errors.append(f"{relative}: proxy admin listener must remain loopback-only")
        return errors
    return [f"{relative}: expected one proxy container"]


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
    if ports.get("health") != 13133:
        errors.append(f"{relative}: Jaeger health port must be named health on 13133")
    for probe_name in ("startupProbe", "livenessProbe", "readinessProbe"):
        probe = _mapping(container.get(probe_name))
        http_get = _mapping(probe.get("httpGet"))
        if http_get.get("path") != "/health/status" or http_get.get("port") != "health":
            errors.append(
                f"{relative}: Jaeger {probe_name} must use the v2 health endpoint"
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


def _check_jaeger_badger_runtime(
    rendered: Documents | str, relative: str
) -> list[str]:
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
    if containers[0].get("image") != JAEGER_V2_IMAGE:
        return [
            f"{relative}: Jaeger must use the digest-pinned 2.20.0 runtime"
        ]
    return []


def _check_prod_jaeger_recovery(
    rendered: Documents | str, relative: str
) -> list[str]:
    deployments = _find(
        _documents(rendered), "Deployment", "ssl-proxy-telemetry-jaeger"
    )
    if not deployments:
        return [f"{relative}: production Jaeger Deployment is missing"]
    containers = [
        container
        for container in _pod_containers(deployments[0])
        if container.get("name") == "jaeger"
    ]
    if len(containers) != 1:
        return [f"{relative}: expected one production Jaeger container"]
    container = containers[0]
    errors: list[str] = []
    memory_request = _quantity_bytes(_path(container, "resources", "requests", "memory"))
    memory_limit = _quantity_bytes(_path(container, "resources", "limits", "memory"))
    if memory_request is None or memory_request < 512 * 1024**2:
        errors.append(
            f"{relative}: production Jaeger needs at least a 512 MiB memory request"
        )
    if memory_limit is None or memory_limit < 2 * 1024**3:
        errors.append(f"{relative}: production Jaeger needs at least a 2 GiB memory limit")
    startup = _mapping(container.get("startupProbe"))
    try:
        startup_budget = int(startup.get("failureThreshold", 0)) * int(
            startup.get("periodSeconds", 0)
        )
    except (TypeError, ValueError):
        startup_budget = 0
    if startup_budget < 1800:
        errors.append(
            f"{relative}: production Jaeger must allow 1800 seconds for Badger recovery"
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
    if secret.get("name") != "postgres-keycloak" or secret.get("key") != "password":
        return [
            f"{relative}: Keycloak database password must come from "
            "postgres-keycloak/password"
        ]
    return []


def _check_prod_alloy_positions(rendered: Documents | str, relative: str) -> list[str]:
    daemon_sets = _find(
        _documents(rendered), "DaemonSet", "ssl-proxy-telemetry-alloy"
    )
    if len(daemon_sets) != 1:
        return [f"{relative}: expected one production Alloy DaemonSet"]
    volumes = _list(_path(daemon_sets[0], "spec", "template", "spec", "volumes"))
    positions = [
        _mapping(volume)
        for volume in volumes
        if _mapping(volume).get("name") == "positions"
    ]
    if (
        len(positions) != 1
        or "emptyDir" not in positions[0]
        or "hostPath" in positions[0]
    ):
        return [
            f"{relative}: production Alloy positions must use emptyDir without hostPath"
        ]
    return []


def _check_prod_keycloak_external_postgres(
    rendered: Documents | str, relative: str
) -> list[str]:
    deployments = _find(
        _documents(rendered), "Deployment", "ssl-proxy-schema-migrator-keycloak"
    )
    if len(deployments) != 1:
        return [f"{relative}: expected one production Keycloak Deployment"]
    pod_spec = _mapping(_path(deployments[0], "spec", "template", "spec"))
    init_container_names = [
        str(_mapping(container).get("name"))
        for container in _list(pod_spec.get("initContainers"))
    ]
    expected_init_order = ["prepare-keycloak-home", "bootstrap-admin-service"]
    errors: list[str] = []
    required_positions = [
        init_container_names.index(name)
        for name in expected_init_order
        if init_container_names.count(name) == 1
    ]
    if (
        len(required_positions) != len(expected_init_order)
        or required_positions != sorted(required_positions)
    ):
        errors.append(
            f"{relative}: Keycloak init containers must prepare keycloak-home "
            "before bootstrap-admin-service"
        )
    container_groups = (
        (
            "bootstrap-admin-service init container",
            _list(pod_spec.get("initContainers")),
            "bootstrap-admin-service",
        ),
        ("keycloak container", _list(pod_spec.get("containers")), "keycloak"),
    )
    expected = {"KC_DB_URL_HOST": "POSTGRES_HOST", "KC_DB_URL_PORT": "POSTGRES_PORT"}
    for description, containers, container_name in container_groups:
        matches = [
            _mapping(container)
            for container in containers
            if _mapping(container).get("name") == container_name
        ]
        if len(matches) != 1:
            errors.append(f"{relative}: expected one Keycloak {description}")
            continue
        environment = _list(matches[0].get("env"))
        for variable, key in expected.items():
            entries = [
                _mapping(entry)
                for entry in environment
                if _mapping(entry).get("name") == variable
            ]
            reference = (
                _mapping(_path(entries[0], "valueFrom", "configMapKeyRef"))
                if len(entries) == 1
                else {}
            )
            if (
                len(entries) != 1
                or "value" in entries[0]
                or reference.get("name") != "ssl-proxy-prod-postgres-endpoint"
                or reference.get("key") != key
            ):
                errors.append(
                    f"{relative}: Keycloak {description} {variable} must come from "
                    f"ssl-proxy-prod-postgres-endpoint/{key}"
                )
        literal_environment = {
            str(_mapping(entry).get("name")): _mapping(entry).get("value")
            for entry in environment
        }
        if literal_environment.get("KC_DB") != "postgres":
            errors.append(
                f"{relative}: Keycloak {description} KC_DB must use the postgres vendor"
            )
        if literal_environment.get("KC_DB_USERNAME") != "keycloak_runtime":
            errors.append(
                f"{relative}: Keycloak {description} must use keycloak_runtime"
            )
        properties = str(literal_environment.get("KC_DB_URL_PROPERTIES", ""))
        for required_property in (
            "sslmode=verify-full",
            "sslrootcert=/var/run/postgres-tls/ca.crt",
        ):
            if required_property not in properties:
                errors.append(
                    f"{relative}: Keycloak {description} KC_DB_URL_PROPERTIES "
                    f"must include {required_property}"
                )
        mounts = {
            str(_mapping(mount).get("name")): _mapping(mount)
            for mount in _list(matches[0].get("volumeMounts"))
        }
        postgres_ca_mount = mounts.get("postgres-ca", {})
        if (
            postgres_ca_mount.get("mountPath") != "/var/run/postgres-tls"
            or postgres_ca_mount.get("readOnly") is not True
        ):
            errors.append(
                f"{relative}: Keycloak {description} must mount postgres-ca read-only"
            )
    volumes = {
        str(_mapping(volume).get("name")): _mapping(volume)
        for volume in _list(pod_spec.get("volumes"))
    }
    postgres_ca_secret = _mapping(volumes.get("postgres-ca", {}).get("secret"))
    if postgres_ca_secret.get("secretName") != "postgres-runtime-tls":
        errors.append(
            f"{relative}: Keycloak postgres-ca must use postgres-runtime-tls"
        )
    return errors


def _check_prod_pgbouncer_external_postgres(
    rendered: Documents | str, relative: str
) -> list[str]:
    documents = _documents(rendered)
    deployments = _find(documents, "Deployment", "postgres-pgbouncer")
    if len(deployments) != 1:
        return [f"{relative}: expected one production PgBouncer Deployment"]
    pod_spec = _mapping(_path(deployments[0], "spec", "template", "spec"))
    init_containers = [
        _mapping(container) for container in _list(pod_spec.get("initContainers"))
    ]
    renderers = [
        container
        for container in init_containers
        if container.get("name") == "render-pgbouncer-config"
    ]
    errors: list[str] = []
    if len(renderers) != 1:
        return [f"{relative}: expected one PgBouncer config renderer"]
    renderer = renderers[0]
    expected = {
        "POSTGRES_HOST": "POSTGRES_HOST",
        "POSTGRES_PORT": "POSTGRES_PORT",
        "POSTGRES_DATABASE": "POSTGRES_DATABASE",
        "POSTGRES_SSL_MODE": "POSTGRES_SSL_MODE",
        "POSTGRES_SSL_SERVER_NAME": "POSTGRES_SSL_SERVER_NAME",
    }
    environment = _list(renderer.get("env"))
    for variable, key in expected.items():
        entries = [
            _mapping(entry)
            for entry in environment
            if _mapping(entry).get("name") == variable
        ]
        reference = (
            _mapping(_path(entries[0], "valueFrom", "configMapKeyRef"))
            if len(entries) == 1
            else {}
        )
        if (
            len(entries) != 1
            or "value" in entries[0]
            or reference.get("name") != "ssl-proxy-prod-postgres-endpoint"
            or reference.get("key") != key
        ):
            errors.append(
                f"{relative}: PgBouncer {variable} must come from "
                f"ssl-proxy-prod-postgres-endpoint/{key}"
            )
    renderer_script = "\n".join(str(arg) for arg in _list(renderer.get("args")))
    for required in (
        "POSTGRES_SSL_MODE",
        "verify-full",
        "POSTGRES_SSL_SERVER_NAME",
        "POSTGRES_HOST",
        "unix_socket_dir = /var/run/pgbouncer",
    ):
        if required not in renderer_script:
            errors.append(
                f"{relative}: PgBouncer config renderer must validate {required}"
            )
    if not re.search(r"busybox@sha256:[0-9a-f]{64}$", str(renderer.get("image", ""))):
        errors.append(f"{relative}: PgBouncer config renderer must use a digest-pinned image")
    pgbouncer_containers = [
        _mapping(container)
        for container in _list(pod_spec.get("containers"))
        if _mapping(container).get("name") == "pgbouncer"
    ]
    if len(pgbouncer_containers) != 1:
        errors.append(f"{relative}: expected one PgBouncer container")
    else:
        security_context = _mapping(pgbouncer_containers[0].get("securityContext"))
        if (
            security_context.get("runAsNonRoot") is not True
            or security_context.get("runAsUser") != 70
            or security_context.get("runAsGroup") != 70
        ):
            errors.append(
                f"{relative}: PgBouncer must use the pinned image's numeric postgres UID/GID 70"
            )
    volumes = {
        str(_mapping(volume).get("name")): _mapping(volume)
        for volume in _list(pod_spec.get("volumes"))
    }
    if "emptyDir" not in volumes.get("generated-config", {}):
        errors.append(f"{relative}: PgBouncer generated-config must use an emptyDir")
    expected_secrets = {
        "users": "pgbouncer-runtime-users",
        "upstream-tls": "postgres-runtime-tls",
    }
    for volume_name, secret_name in expected_secrets.items():
        secret = _mapping(volumes.get(volume_name, {}).get("secret"))
        if secret.get("secretName") != secret_name:
            errors.append(
                f"{relative}: PgBouncer {volume_name} must use {secret_name}"
            )
    if _find(documents, "ConfigMap", "postgres-pgbouncer-config"):
        errors.append(
            f"{relative}: PgBouncer must not route to a hard-coded ConfigMap name"
        )
    return errors


OCTOPUS_RUNTIME_PROCESSORS = {
    "sync-scan-ingestion",
    "sync-job-planner",
    "sync-backlog-recovery",
    "sync-load-dispatch",
    "sync-load-consumer",
    "sync-result-consumer",
    "sync-outbox-publisher",
    "wireless-frame-normalizer",
    "wireless-inventory-projector",
    "wireless-identity-projector",
    "embedding-preparer",
    "embedding-text-builder",
    "behavior-projector",
    "timing-projector",
    "baseline-projector",
    "sequence-projector",
    "graph-projector",
    "similarity-projector",
    "clustering-projector",
    "dns-alert-projector",
    "rf-alert-projector",
    "risk-projector",
    "event-retention",
    "search-retention",
    "stale-worker-cleanup",
    "scheduled-reconciliation",
}


def _check_octopus_runtime(
    rendered: Documents | str, relative: str
) -> list[str]:
    deployments = _find(
        _documents(rendered), "Deployment", "ssl-proxy-java-coordinator"
    )
    if len(deployments) != 1:
        return [f"{relative}: expected one Octopus Deployment"]
    containers = [
        container
        for container in _pod_containers(deployments[0])
        if container.get("name") == "java-coordinator"
    ]
    if len(containers) != 1:
        return [f"{relative}: expected one Octopus container"]
    environment = _list(containers[0].get("env"))
    expected_environment = "development" if "/dev" in relative else "production"
    expected = {
        "POSTGRES_ENABLED": "true",
        "SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR": "1",
        "OCTOPUS_PROCESSORS_ENABLED": "true",
        "OCTOPUS_CONSUMERS_ENABLED": "true",
        "OCTOPUS_ARCHIVE_ENABLED": "true",
        "OCTOPUS_ENVIRONMENT": expected_environment,
    }
    errors: list[str] = []
    if (
        expected_environment == "production"
        and _path(deployments[0], "spec", "replicas") != 3
    ):
        errors.append(f"{relative}: production Octopus requires exactly 3 replicas")
    for variable, value in expected.items():
        entries = [
            _mapping(entry)
            for entry in environment
            if _mapping(entry).get("name") == variable
        ]
        if len(entries) != 1 or entries[0].get("value") != value:
            errors.append(
                f"{relative}: Octopus runtime requires {variable}={value}"
            )

    names = {
        str(_mapping(entry).get("name"))
        for entry in environment
        if _mapping(entry).get("name") is not None
    }
    processor_entries = [
        _mapping(entry)
        for entry in environment
        if _mapping(entry).get("name") == "OCTOPUS_ENABLED_PROCESSORS"
    ]
    configured_processors = (
        {
            value.strip()
            for value in str(processor_entries[0].get("value", "")).split(",")
            if value.strip()
        }
        if len(processor_entries) == 1
        else set()
    )
    if configured_processors != OCTOPUS_RUNTIME_PROCESSORS:
        missing = sorted(OCTOPUS_RUNTIME_PROCESSORS - configured_processors)
        extra = sorted(configured_processors - OCTOPUS_RUNTIME_PROCESSORS)
        errors.append(
            f"{relative}: Octopus must enable the complete processor catalog; "
            f"missing={','.join(missing) or '-'} extra={','.join(extra) or '-'}"
        )
    unexpected = sorted(name for name in names if name.startswith("OCTOPUS_CUTOVER_"))
    if unexpected:
        errors.append(
            f"{relative}: Octopus contains retired cutover inputs: "
            f"{', '.join(unexpected)}"
        )
    return errors


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
    for environment in ("prod",):
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


def _check_standard_labels(
    rendered: Documents | str, relative: str
) -> list[str]:
    errors: list[str] = []
    for document in _documents(rendered):
        kind = str(document.get("kind", ""))
        if kind not in STANDARD_LABELED_KINDS:
            continue
        name = str(_metadata(document).get("name", "<unnamed>"))
        if kind == "ConfigMap" and re.search(r"-[a-z0-9]{10}$", name):
            # Generated ConfigMaps are content-addressed implementation details.
            # Their owning workloads and handwritten ConfigMaps remain enforced.
            continue
        labels = _mapping(_metadata(document).get("labels"))
        missing = [key for key in STANDARD_LABEL_KEYS if key not in labels]
        if missing:
            errors.append(
                f"{relative}: {kind}/{name} is missing standard labels: "
                + ", ".join(missing)
            )
    return errors


def _check_ingress_policy_coverage(
    rendered: Documents | str, relative: str
) -> list[str]:
    documents = _documents(rendered)
    errors: list[str] = []
    selectors: list[Mapping[str, Any]] = []
    has_default_deny = False
    for document in documents:
        if document.get("kind") != "NetworkPolicy":
            continue
        spec = _mapping(document.get("spec"))
        policy_types = {str(value) for value in _list(spec.get("policyTypes"))}
        if "Ingress" not in policy_types:
            continue
        pod_selector = spec.get("podSelector")
        selector = _mapping(_path(spec, "podSelector", "matchLabels"))
        if selector:
            selectors.append(selector)
        elif (
            isinstance(pod_selector, Mapping)
            and not selector
            and not _list(pod_selector.get("matchExpressions"))
            and ("ingress" not in spec or spec.get("ingress") == [])
        ):
            has_default_deny = True

    for document in documents:
        if document.get("kind") not in {"DaemonSet", "Deployment", "Job", "StatefulSet"}:
            continue
        labels = _mapping(_path(document, "spec", "template", "metadata", "labels"))
        if not any(
            all(labels.get(key) == value for key, value in selector.items())
            for selector in selectors
        ):
            errors.append(
                f"{relative}: {document.get('kind')}/{_metadata(document).get('name')} "
                "has no explicit ingress NetworkPolicy"
            )
    if relative == "cyber-stack/matrix/prod" and not has_default_deny:
        errors.append(f"{relative}: namespace ingress default-deny policy is missing")
    return errors


def _check_traefik_redirect(rendered: Documents | str, relative: str) -> list[str]:
    if any("entrypoints.web.http.redirections.entrypoint.port" in value for value in _strings(_documents(rendered))):
        return [f"{relative}: Traefik entrypoint.port is not a supported redirection field"]
    return []


def _workload_pod_spec(document: Mapping[str, Any]) -> Mapping[str, Any]:
    if document.get("kind") == "Pod":
        return _mapping(document.get("spec"))
    if document.get("kind") == "CronJob":
        return _mapping(
            _path(document, "spec", "jobTemplate", "spec", "template", "spec")
        )
    return _mapping(_path(document, "spec", "template", "spec"))


def _check_phase_one_workload_edge(
    rendered: Documents | str, relative: str
) -> list[str]:
    errors: list[str] = []
    for document in _documents(rendered):
        kind = str(document.get("kind", ""))
        name = str(_metadata(document).get("name", "<unnamed>"))
        if kind == "Service":
            service_type = _path(document, "spec", "type")
            if service_type not in (None, "ClusterIP"):
                errors.append(
                    f"{relative}: phase one Service {name} must be ClusterIP or "
                    f"headless, not {service_type}"
                )
        if kind in PHASE_ONE_ROUTE_KINDS and (kind, name) not in PHASE_ONE_ROUTE_ALLOWLIST:
            errors.append(
                f"{relative}: phase one must not render HTTP route resource "
                f"{kind}/{name}"
            )

        pod_spec = _workload_pod_spec(document)
        if not pod_spec:
            continue
        if pod_spec.get("hostNetwork") is True and (
            kind,
            name,
        ) not in PHASE_ONE_HOST_NETWORK_ALLOWLIST:
            errors.append(
                f"{relative}: phase one workload {kind}/{name} uses "
                "unapproved hostNetwork"
            )
        containers = [
            _mapping(container)
            for field in ("initContainers", "containers", "ephemeralContainers")
            for container in _list(pod_spec.get(field))
        ]
        for container in containers:
            for port in _list(container.get("ports")):
                definition = _mapping(port)
                if definition.get("hostPort") is None:
                    continue
                if str(definition.get("protocol", "TCP")).upper() == "TCP":
                    errors.append(
                        f"{relative}: phase one workload {kind}/{name} exposes "
                        f"TCP hostPort {definition.get('hostPort')}"
                    )
    return errors


def _traefik_values(
    rendered: Documents | str, relative: str, errors: list[str]
) -> Mapping[str, Any] | None:
    charts = _find(_documents(rendered), "HelmChartConfig", "traefik")
    if len(charts) != 1:
        errors.append(
            f"{relative}: expected exactly one kube-system HelmChartConfig/traefik"
        )
        return None
    if _metadata(charts[0]).get("namespace") != "kube-system":
        errors.append(
            f"{relative}: HelmChartConfig/traefik must be in kube-system"
        )
    values_content = _path(charts[0], "spec", "valuesContent")
    if not isinstance(values_content, str):
        errors.append(
            f"{relative}: HelmChartConfig/traefik must provide valuesContent"
        )
        return None
    values_documents = _load_documents(
        values_content, f"{relative}: HelmChartConfig/traefik valuesContent", errors
    )
    if not values_documents or len(values_documents) != 1:
        errors.append(
            f"{relative}: HelmChartConfig/traefik valuesContent must be one mapping"
        )
        return None
    return values_documents[0]


def _check_default_deny_traefik(
    rendered: Documents | str, relative: str
) -> list[str]:
    errors: list[str] = []
    values = _traefik_values(rendered, relative, errors)
    if values is None:
        return errors

    false_paths = (
        ("global", "checkNewVersion"),
        ("global", "sendAnonymousUsage"),
        ("api", "dashboard"),
        ("api", "insecure"),
        ("api", "debug"),
        ("gateway", "enabled"),
        ("gatewayClass", "enabled"),
        ("ingressClass", "isDefaultClass"),
        ("ingressRoute", "dashboard", "enabled"),
        ("ingressRoute", "healthcheck", "enabled"),
        ("experimental", "kubernetesGateway", "enabled"),
        ("ports", "websecure", "http3", "enabled"),
        ("hostNetwork",),
        ("persistence", "enabled"),
    )
    for path in false_paths:
        if _path(values, *path) is not False:
            errors.append(
                f"{relative}: Traefik {'.'.join(path)} must be explicitly false"
            )

    if _path(values, "ingressClass", "enabled") is not True:
        errors.append(
            f"{relative}: Traefik must retain a non-default IngressClass"
        )

    for provider in (
        "kubernetesCRD",
        "kubernetesGateway",
        "kubernetesIngressNGINX",
        "file",
    ):
        if _path(values, "providers", provider, "enabled") is not False:
            errors.append(
                f"{relative}: Traefik provider {provider} must be disabled"
            )

    access_log = _mapping(_path(values, "logs", "access"))
    if _path(values, "logs", "general", "format") != "json":
        errors.append(f"{relative}: Traefik general logs must use JSON")
    if access_log.get("enabled") is not True or access_log.get("format") != "json":
        errors.append(
            f"{relative}: Traefik JSON access logging to stdout must be enabled"
        )
    if access_log.get("filePath") not in (None, ""):
        errors.append(f"{relative}: Traefik access logs must remain on stdout")
    if _path(access_log, "fields", "headers", "defaultmode") != "drop":
        errors.append(
            f"{relative}: Traefik access logs must drop request and response headers"
        )
    if _path(values, "metrics", "prometheus", "service", "enabled") is not True:
        errors.append(
            f"{relative}: Traefik must expose an internal Prometheus metrics Service"
        )

    exposed_ports: set[tuple[str, Any, str]] = set()
    for name, port in _mapping(values.get("ports")).items():
        definition = _mapping(port)
        if _path(definition, "expose", "default") is True:
            exposed_ports.add(
                (
                    str(name),
                    definition.get("exposedPort"),
                    str(definition.get("protocol", "TCP")).upper(),
                )
            )
    expected_ports = {("web", 80, "TCP"), ("websecure", 443, "TCP")}
    if exposed_ports != expected_ports:
        errors.append(
            f"{relative}: Traefik public ports must be exactly TCP 80/443"
        )

    for entrypoint in ("web", "websecure"):
        port = _mapping(_path(values, "ports", entrypoint))
        if port.get("allowACMEByPass") is not False:
            errors.append(
                f"{relative}: Traefik {entrypoint} ACME bypass must be disabled"
            )
        if _path(port, "forwardedHeaders", "insecure") is not False or _list(
            _path(port, "forwardedHeaders", "trustedIPs")
        ):
            errors.append(
                f"{relative}: Traefik {entrypoint} forwarded headers must be untrusted"
            )
        if _path(port, "proxyProtocol", "insecure") is not False or _list(
            _path(port, "proxyProtocol", "trustedIPs")
        ):
            errors.append(
                f"{relative}: Traefik {entrypoint} proxy protocol must be untrusted"
            )
        expected_timeouts = {
            "readTimeout": "15s",
            "writeTimeout": "30s",
            "idleTimeout": "30s",
        }
        if _mapping(_path(port, "transport", "respondingTimeouts")) != expected_timeouts:
            errors.append(
                f"{relative}: Traefik {entrypoint} responding timeouts must remain finite"
            )

    if _mapping(_path(values, "ports", "web", "http", "redirections", "entryPoint")):
        errors.append(f"{relative}: phase one Traefik must not redirect HTTP")
    if _path(values, "ports", "websecure", "http", "tls", "certResolver") not in (
        None,
        "",
    ):
        errors.append(f"{relative}: phase one Traefik must not configure ACME")
    if _path(values, "ports", "websecure", "http", "tls", "enabled") is not True:
        errors.append(
            f"{relative}: Traefik websecure must terminate TLS with its default certificate"
        )
    for field in ("certificatesResolvers", "tlsOptions", "tlsStore"):
        if _mapping(values.get(field)):
            errors.append(f"{relative}: phase one Traefik {field} must be empty")

    service_spec = _mapping(_path(values, "service", "spec"))
    expected_service = {
        "type": "LoadBalancer",
        "externalTrafficPolicy": "Local",
        "ipFamilyPolicy": "SingleStack",
        "ipFamilies": ["IPv4"],
    }
    if service_spec != expected_service:
        errors.append(
            f"{relative}: Traefik Service must be IPv4 SingleStack with "
            "externalTrafficPolicy Local"
        )
    for field in ("additionalArguments", "env", "envFrom"):
        if values.get(field) not in (None, [], {}):
            errors.append(
                f"{relative}: phase one Traefik must not inject {field} overrides"
            )
    if _mapping(_path(values, "service", "additionalServices")):
        errors.append(
            f"{relative}: phase one Traefik must not expose additional Services"
        )

    requests = _mapping(_path(values, "resources", "requests"))
    limits = _mapping(_path(values, "resources", "limits"))
    if requests != {"cpu": "100m", "memory": "128Mi"} or limits != {
        "cpu": "500m",
        "memory": "256Mi",
    }:
        errors.append(f"{relative}: Traefik resource bounds must be preserved")
    return errors


def _check_traefik_observability(
    rendered: Documents | str, relative: str
) -> list[str]:
    config_maps = [
        document
        for document in _documents(rendered)
        if document.get("kind") == "ConfigMap"
        and str(_metadata(document).get("name", "")).startswith(
            "ssl-proxy-telemetry-prometheus-config-"
        )
    ]
    if not config_maps:
        return []
    errors: list[str] = []
    data = _mapping(config_maps[0].get("data"))
    prometheus_documents = _load_documents(
        str(data.get("prometheus.yml", "")),
        f"{relative}: Prometheus configuration",
        errors,
    )
    rule_maps = [
        document
        for document in _documents(rendered)
        if document.get("kind") == "ConfigMap"
        and str(_metadata(document).get("name", "")).startswith(
            "ssl-proxy-telemetry-prometheus-rules-"
        )
    ]
    rules_content = "\n---\n".join(
        str(value)
        for document in rule_maps
        for value in _mapping(document.get("data")).values()
    )
    rules_documents = _load_documents(
        rules_content,
        f"{relative}: Traefik edge rules",
        errors,
    )
    if not prometheus_documents or not rules_documents:
        return errors
    prometheus = prometheus_documents[0]
    if "/etc/prometheus/rules/*.yml" not in _list(prometheus.get("rule_files")):
        errors.append(f"{relative}: Prometheus must load generated rule files")
    jobs = [
        _mapping(job)
        for job in _list(prometheus.get("scrape_configs"))
        if _mapping(job).get("job_name") == "traefik-edge"
    ]
    targets = {
        str(target)
        for job in jobs
        for config in _list(job.get("static_configs"))
        for target in _list(_mapping(config).get("targets"))
    }
    if jobs == [] or targets != {
        "traefik-metrics.kube-system.svc.cluster.local:9100"
    }:
        errors.append(
            f"{relative}: Prometheus must scrape only the internal Traefik metrics Service"
        )

    rules = [
        _mapping(rule)
        for rules_document in rules_documents
        for group in _list(rules_document.get("groups"))
        for rule in _list(_mapping(group).get("rules"))
    ]
    expressions = {str(rule.get("alert")): str(rule.get("expr", "")) for rule in rules}
    required = {
        "TraefikEdgeDown": ('up{job="traefik-edge"}',),
        "TraefikEdgeRequestFlood": ("traefik_entrypoint_requests_total",),
        "TraefikEdgeUnexpectedResponse": (
            "traefik_entrypoint_requests_total",
            'code!="404"',
        ),
    }
    for alert, fragments in required.items():
        expression = expressions.get(alert, "")
        if not all(fragment in expression for fragment in fragments):
            errors.append(
                f"{relative}: Prometheus alert {alert} is missing or ineffective"
            )
    return errors


def _config_maps_with_prefix(
    rendered: Documents | str, prefix: str
) -> list[Document]:
    return [
        document
        for document in _documents(rendered)
        if document.get("kind") == "ConfigMap"
        and str(_metadata(document).get("name", "")).startswith(prefix)
    ]


def _workload_pod_specs(documents: Iterable[Document]) -> Iterable[Mapping[str, Any]]:
    for document in documents:
        kind = document.get("kind")
        if kind == "Pod":
            yield _mapping(document.get("spec"))
        elif kind == "CronJob":
            yield _mapping(
                _path(document, "spec", "jobTemplate", "spec", "template", "spec")
            )
        elif kind in {"DaemonSet", "Deployment", "Job", "ReplicaSet", "StatefulSet"}:
            yield _mapping(_path(document, "spec", "template", "spec"))


def _check_immutable_image_pulls(
    rendered: Documents | str, relative: str
) -> list[str]:
    errors: list[str] = []
    for pod_spec in _workload_pod_specs(_documents(rendered)):
        containers = (
            _list(pod_spec.get("initContainers"))
            + _list(pod_spec.get("containers"))
            + _list(pod_spec.get("ephemeralContainers"))
        )
        for container in containers:
            definition = _mapping(container)
            name = str(definition.get("name", "<unnamed>"))
            image = str(definition.get("image", ""))
            if re.search(r"@sha256:[0-9a-f]{64}$", image) is None:
                errors.append(
                    f"{relative}: container {name} image is not digest pinned: {image}"
                )
            if definition.get("imagePullPolicy") != "IfNotPresent":
                errors.append(
                    f"{relative}: digest-pinned container {name} must use "
                    "imagePullPolicy IfNotPresent"
                )
    return errors


def _workloads_source_secret_key(
    documents: Iterable[Document], secret_name: str, secret_key: str
) -> bool:
    for pod_spec in _workload_pod_specs(documents):
        containers = (
            _list(pod_spec.get("initContainers"))
            + _list(pod_spec.get("containers"))
            + _list(pod_spec.get("ephemeralContainers"))
        )
        for container in containers:
            definition = _mapping(container)
            for entry in _list(definition.get("env")):
                secret_ref = _mapping(
                    _path(_mapping(entry), "valueFrom", "secretKeyRef")
                )
                if (
                    secret_ref.get("name") == secret_name
                    and secret_ref.get("key") == secret_key
                ):
                    return True
            for entry in _list(definition.get("envFrom")):
                if _path(_mapping(entry), "secretRef", "name") == secret_name:
                    return True
        for volume in _list(pod_spec.get("volumes")):
            volume_definition = _mapping(volume)
            secret = _mapping(volume_definition.get("secret"))
            if secret.get("secretName") == secret_name:
                items = [_mapping(item) for item in _list(secret.get("items"))]
                if not items or any(item.get("key") == secret_key for item in items):
                    return True
            for source in _list(_path(volume_definition, "projected", "sources")):
                projected_secret = _mapping(_mapping(source).get("secret"))
                if projected_secret.get("name") != secret_name:
                    continue
                items = [
                    _mapping(item) for item in _list(projected_secret.get("items"))
                ]
                if not items or any(item.get("key") == secret_key for item in items):
                    return True
    return False


def _check_observability_contract(
    rendered: Documents | str, relative: str
) -> list[str]:
    documents = _documents(rendered)
    errors: list[str] = []
    catalog_maps = _config_maps_with_prefix(
        documents, "ssl-proxy-telemetry-prometheus-catalog-"
    )
    if len(catalog_maps) != 1:
        errors.append(f"{relative}: expected one generated observability service catalog")
    else:
        data = _mapping(catalog_maps[0].get("data"))
        catalog: list[object] = []
        for key, raw_catalog in data.items():
            if not str(key).endswith("service-catalog.yml"):
                continue
            try:
                loaded_catalog = yaml.safe_load(str(raw_catalog))
            except yaml.YAMLError as exc:
                errors.append(
                    f"{relative}: invalid observability service catalog {key}: {exc}"
                )
                continue
            if isinstance(loaded_catalog, list):
                catalog.extend(loaded_catalog)
        services = {
            str(_path(entry, "labels", "service"))
            for entry in (catalog or [])
            if _path(entry, "labels", "service") is not None
        }
        missing = sorted(OBSERVABILITY_CATALOG_SERVICES - services)
        if missing:
            errors.append(
                f"{relative}: observability catalog is missing: {', '.join(missing)}"
            )
        if "/prod" in relative and "postgres-external" not in services:
            errors.append(
                f"{relative}: production observability catalog is missing: postgres-external"
            )
        if "/dev" in relative and "postgres-external" in services:
            errors.append(
                f"{relative}: development observability catalog must not probe postgres-external"
            )

    generated_prefixes = (
        "ssl-proxy-telemetry-prometheus-config-",
        "ssl-proxy-telemetry-prometheus-rules-",
        "ssl-proxy-telemetry-alertmanager-config-",
        "ssl-proxy-telemetry-grafana-dashboards-",
        "ssl-proxy-telemetry-otel-collector-config-",
        "ssl-proxy-telemetry-jaeger-config-",
        "ssl-proxy-telemetry-blackbox-config-",
    )
    config_map_names = {
        str(_metadata(document).get("name", ""))
        for document in documents
        if document.get("kind") == "ConfigMap"
    }
    for prefix in generated_prefixes:
        names = [name for name in config_map_names if name.startswith(prefix)]
        if len(names) != 1 or not re.fullmatch(re.escape(prefix) + r"[a-z0-9]{10}", names[0]):
            errors.append(f"{relative}: {prefix.removesuffix('-')} must have one Kustomize content hash")

    required_policies = {
        "ssl-proxy-telemetry-prometheus",
        "ssl-proxy-telemetry-alertmanager",
        "ssl-proxy-telemetry-blackbox-exporter",
        "ssl-proxy-telemetry-kube-state-metrics",
        "ssl-proxy-redis-runtime",
        "ssl-proxy-minio-ingress",
    }
    policies = {
        str(_metadata(document).get("name"))
        for document in documents
        if document.get("kind") == "NetworkPolicy"
    }
    missing_policies = sorted(required_policies - policies)
    if missing_policies:
        errors.append(
            f"{relative}: observability NetworkPolicies are missing: "
            + ", ".join(missing_policies)
        )

    for key in ("alertmanager-webhook-url", "jenkins-prometheus-password"):
        if not _workloads_source_secret_key(
            documents, "observability-credentials", key
        ):
            errors.append(f"{relative}: required observability Secret key {key} is not mounted")
    return errors


def _check_postgres_collection_path(
    rendered: Documents | str, relative: str, environment: str
) -> list[str]:
    documents = _documents(rendered)
    errors: list[str] = []
    bridges = _find(
        documents, "Deployment", "ssl-proxy-telemetry-postgres-metrics-bridge"
    )
    if len(bridges) != 1:
        return [f"{relative}: expected one PostgreSQL metrics bridge declaration"]
    bridge = bridges[0]
    replicas = _path(bridge, "spec", "replicas")
    pod_spec = _mapping(_path(bridge, "spec", "template", "spec"))
    bundled = _find(documents, "StatefulSet", "ssl-proxy-postgres")
    if environment == "dev":
        if len(bundled) != 1:
            errors.append(f"{relative}: dev must render bundled PostgreSQL for direct scraping")
        if replicas != 0:
            errors.append(f"{relative}: dev PostgreSQL host metrics bridge must remain disabled")
    else:
        if bundled:
            errors.append(f"{relative}: prod must not render bundled PostgreSQL")
        if replicas != 1 or pod_spec.get("hostNetwork") is not True:
            errors.append(f"{relative}: prod PostgreSQL metrics bridge must run once with hostNetwork")
        if _path(pod_spec, "nodeSelector", "ssl-proxy.io/postgres-host") != "true":
            errors.append(
                f"{relative}: prod PostgreSQL bridge requires ssl-proxy.io/postgres-host=true"
            )
        if _path(bridge, "spec", "strategy", "type") != "Recreate":
            errors.append(
                f"{relative}: prod PostgreSQL bridge must use Recreate to avoid host-port rollout deadlock"
            )
    bridge_configs = _config_maps_with_prefix(
        documents, "ssl-proxy-telemetry-postgres-bridge-config-"
    )
    bridge_text = "\n".join(
        str(value)
        for document in bridge_configs
        for value in _mapping(document.get("data")).values()
    )
    if "127.0.0.1:10080" not in bridge_text or "/api/v1/write" not in bridge_text:
        errors.append(f"{relative}: PostgreSQL bridge must scrape host-local status and remote-write")
    prometheus_configs = _config_maps_with_prefix(
        documents, "ssl-proxy-telemetry-prometheus-config-"
    )
    prometheus_text = "\n".join(
        str(value)
        for document in prometheus_configs
        for value in _mapping(document.get("data")).values()
    )
    if environment == "dev" and "job_name: postgres-dev" not in prometheus_text:
        errors.append(f"{relative}: Prometheus must retain direct dev PostgreSQL discovery")
    return errors


def _wave(document: Mapping[str, Any]) -> int | None:
    value = _mapping(_metadata(document).get("annotations")).get("argocd.argoproj.io/sync-wave")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _check_postgres_waves(rendered: Documents | str, relative: str) -> list[str]:
    documents = _documents(rendered)
    schema_jobs = _find(documents, "Job", "ssl-proxy-postgres-schema-executor")
    bootstrap_jobs = _find(documents, "Job", "ssl-proxy-postgres-bootstrap") or _find(
        documents, "Job", "ssl-proxy-postgres-init"
    )
    if not schema_jobs or not bootstrap_jobs:
        return []
    bootstrap_waves = [wave for document in bootstrap_jobs if (wave := _wave(document)) is not None]
    schema_waves = [wave for document in schema_jobs if (wave := _wave(document)) is not None]
    if not bootstrap_waves or not schema_waves:
        return []
    init_wave = max(bootstrap_waves)
    schema_wave = max(schema_waves)
    errors: list[str] = []
    if init_wave >= schema_wave:
        errors.append(f"{relative}: PostgreSQL init wave ({init_wave}) must be less than schema executor wave ({schema_wave})")
    grants_jobs = _find(documents, "Job", "ssl-proxy-postgres-init-grants")
    grants_waves = [wave for document in grants_jobs if (wave := _wave(document)) is not None]
    if grants_waves and schema_wave >= max(grants_waves):
        errors.append(f"{relative}: schema executor wave ({schema_wave}) must be less than grants wave ({max(grants_waves)})")
    return errors


def _check_postgres_plaintext_contract(
    rendered: Documents | str, relative: str
) -> list[str]:
    documents = _documents(rendered)
    rendered_text = yaml.safe_dump(documents, sort_keys=False)
    errors: list[str] = []
    for forbidden in (
        "postgres-client-ca",
        "POSTGRES_TLS_CA_FILE",
        "POSTGRES_TLS_SERVER_NAME",
        "sslMode=VERIFY_IDENTITY",
    ):
        if forbidden in rendered_text:
            errors.append(f"{relative}: rendered PostgreSQL workload retains {forbidden}")

    octopus = _find(documents, "Deployment", "ssl-proxy-java-coordinator")
    if octopus:
        ssl_modes = [
            entry.get("value")
            for entry in _environment(_pod_containers(octopus[0]))
            if entry.get("name") == "POSTGRES_SSL_MODE"
        ]
        if ssl_modes != ["disable"]:
            errors.append(f"{relative}: Octopus must set POSTGRES_SSL_MODE=disable")
    return errors


def _schema_migrator_contract_marker(root: Path, errors: list[str]) -> str | None:
    relative = "sql/postgres/schema_migrator/manifest.yaml"
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


def _octopus_contract_checksum(root: Path, errors: list[str]) -> str | None:
    relative = "sql/postgres/octopus_core/manifest.yaml"
    text = _read_required(root, relative, errors, "manifest")
    if text is None:
        return None
    documents = _load_documents(text, relative, errors)
    if not documents:
        return None
    checksum = documents[0].get("manifest_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(checksum)):
        errors.append(f"{relative}: missing canonical manifest checksum")
        return None
    return str(checksum)


def _check_octopus_schema_contract(
    rendered: Documents | str, relative: str, expected_checksum: str
) -> list[str]:
    deployments = _find(
        _documents(rendered), "Deployment", "ssl-proxy-java-coordinator"
    )
    if len(deployments) != 1:
        return [f"{relative}: expected one Octopus Deployment"]
    containers = [
        container
        for container in _pod_containers(deployments[0])
        if container.get("name") == "java-coordinator"
    ]
    if len(containers) != 1:
        return [f"{relative}: expected one Octopus container"]
    entries = [
        _mapping(entry)
        for entry in _environment(containers)
        if _mapping(entry).get("name") == "POSTGRES_SCHEMA_MANIFEST_SHA256"
    ]
    if len(entries) != 1 or entries[0].get("value") != expected_checksum:
        return [
            f"{relative}: Octopus POSTGRES_SCHEMA_MANIFEST_SHA256 must equal "
            "sql/postgres/octopus_core/manifest.yaml"
        ]
    return []


def _check_schema_executor_contract(rendered: Documents | str, relative: str, expected_marker: str) -> list[str]:
    jobs = _find(_documents(rendered), "Job", "ssl-proxy-postgres-schema-executor")
    if len(jobs) != 1:
        return [f"{relative}: expected one rendered PostgreSQL schema executor Job"]
    job = jobs[0]
    errors: list[str] = []
    marker = _path(job, "spec", "template", "metadata", "annotations", "ssl-proxy.io/content-hash")
    if marker != expected_marker:
        errors.append(f"{relative}: schema executor content-hash must equal canonical contract {expected_marker}")
    images = [str(container.get("image", "")) for container in _pod_containers(job)]
    if not any(re.search(r"postgres-runtime-schema@sha256:[0-9a-f]{64}$", image) for image in images):
        errors.append(f"{relative}: schema executor must use a digest-pinned image")
    containers = [
        container
        for container in _pod_containers(job)
        if container.get("name") == "schema"
    ]
    if len(containers) != 1:
        errors.append(f"{relative}: expected one schema executor container")
        return errors
    expected_endpoint_environment = {
        "POSTGRES_HOST": "POSTGRES_HOST",
        "POSTGRES_PORT": "POSTGRES_PORT",
        "POSTGRES_DATABASE": "POSTGRES_DATABASE",
        "PGSSLMODE": "POSTGRES_SSL_MODE",
        "POSTGRES_SSL_SERVER_NAME": "POSTGRES_SSL_SERVER_NAME",
    }
    environment = _list(containers[0].get("env"))
    for variable, key in expected_endpoint_environment.items():
        entries = [
            _mapping(entry)
            for entry in environment
            if _mapping(entry).get("name") == variable
        ]
        reference = (
            _mapping(_path(entries[0], "valueFrom", "configMapKeyRef"))
            if len(entries) == 1
            else {}
        )
        if (
            len(entries) != 1
            or "value" in entries[0]
            or reference.get("name") != "ssl-proxy-prod-postgres-endpoint"
            or reference.get("key") != key
        ):
            errors.append(
                f"{relative}: schema executor {variable} must come from "
                f"ssl-proxy-prod-postgres-endpoint/{key} without a literal value"
            )
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


def _check_platform_bootstrap_application(
    documents: Documents, errors: list[str]
) -> None:
    relative = "cyber-stack/argocd-bootstrap"
    applications = [
        document for document in documents if document.get("kind") == "Application"
    ]
    if (
        len(documents) != 1
        or len(applications) != 1
        or _metadata(applications[0]).get("name")
        != PLATFORM_BOOTSTRAP_APPLICATION
    ):
        errors.append(
            f"{relative}: expected only one {PLATFORM_BOOTSTRAP_APPLICATION} Application"
        )
        return

    application = applications[0]
    source = _mapping(_path(application, "spec", "source"))
    destination = _mapping(_path(application, "spec", "destination"))
    automated = _mapping(_path(application, "spec", "syncPolicy", "automated"))
    required = {
        "metadata.namespace: argocd": _metadata(application).get("namespace")
        == "argocd",
        "project: default": _path(application, "spec", "project") == "default",
        "repoURL: https://github.com/zlovtnik/ssl-proxy.git": source.get(
            "repoURL"
        )
        == "https://github.com/zlovtnik/ssl-proxy.git",
        "targetRevision: main": source.get("targetRevision") == "main",
        "path: cyber-stack/argocd": source.get("path")
        == "cyber-stack/argocd",
        "destination.server: https://kubernetes.default.svc": destination.get(
            "server"
        )
        == "https://kubernetes.default.svc",
        "destination.namespace: argocd": destination.get("namespace")
        == "argocd",
        "automated.enabled must not be false": automated.get("enabled") is not False,
        "automated.prune: false": automated.get("prune") is False,
        "automated.selfHeal: true": automated.get("selfHeal") is True,
        "automated.allowEmpty: false": automated.get("allowEmpty") is False,
    }
    for contract, valid in required.items():
        if not valid:
            errors.append(f"{relative}: bootstrap Application must set {contract}")
    if "kustomize" not in source or "directory" in source:
        errors.append(f"{relative}: bootstrap Application must use Kustomize")
    sync_options = {
        str(option)
        for option in _list(_path(application, "spec", "syncPolicy", "syncOptions"))
    }
    required_options = {"ApplyOutOfSyncOnly=true", "ServerSideApply=true"}
    if not required_options.issubset(sync_options):
        errors.append(
            f"{relative}: bootstrap Application sync options are not preserved"
        )
    if "CreateNamespace=true" in sync_options:
        errors.append(
            f"{relative}: argocd namespace must be provided by the platform"
        )
    finalizers = {
        str(finalizer) for finalizer in _list(_metadata(application).get("finalizers"))
    }
    if any(
        finalizer.startswith("resources-finalizer.argocd.argoproj.io")
        for finalizer in finalizers
    ):
        errors.append(
            f"{relative}: bootstrap Application must not cascade-delete its control plane"
        )


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
    allowed_resources = [
        _mapping(resource)
        for resource in _list(_path(projects[0], "spec", "namespaceResourceWhitelist"))
    ]
    allowed_route_kinds = {kind for kind, _ in PHASE_ONE_ROUTE_ALLOWLIST}
    if any(
        resource.get("group") == "*"
        or resource.get("kind") == "*"
        or (
            str(resource.get("kind")) in PHASE_ONE_ROUTE_KINDS
            and str(resource.get("kind")) not in allowed_route_kinds
        )
        for resource in allowed_resources
    ):
        errors.append(
            f"{relative}: ssl-proxy AppProject must not allow phase-one route kinds"
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


def _check_production_gate_rbac(documents: Documents, errors: list[str]) -> None:
    relative = "cyber-stack/argocd"
    name = "ssl-proxy-production-gate"
    service_accounts = _find(documents, "ServiceAccount", name)
    roles = _find(documents, "Role", name)
    role_bindings = _find(documents, "RoleBinding", name)
    if len(service_accounts) != 1 or len(roles) != 1 or len(role_bindings) != 1:
        errors.append(
            f"{relative}: production gate requires exactly one ServiceAccount, Role, and RoleBinding"
        )
        return
    if _metadata(service_accounts[0]).get("namespace") != "argocd":
        errors.append(f"{relative}: production gate ServiceAccount must be in argocd")
    if service_accounts[0].get("automountServiceAccountToken") is not False:
        errors.append(
            f"{relative}: production gate ServiceAccount must disable automatic token mounts"
        )

    expected_rule = {
        "apiGroups": ["argoproj.io"],
        "resources": ["applications"],
        "resourceNames": list(WORKLOAD_APPLICATIONS),
        "verbs": ["get"],
    }
    if _metadata(roles[0]).get("namespace") != "argocd" or roles[0].get("rules") != [expected_rule]:
        errors.append(
            f"{relative}: production gate Role may only get the three production Applications"
        )

    role_binding = role_bindings[0]
    expected_role_ref = {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": name,
    }
    expected_subject = {
        "kind": "ServiceAccount",
        "name": name,
        "namespace": "argocd",
    }
    if (
        _metadata(role_binding).get("namespace") != "argocd"
        or role_binding.get("roleRef") != expected_role_ref
        or role_binding.get("subjects") != [expected_subject]
    ):
        errors.append(
            f"{relative}: production gate RoleBinding must bind only its dedicated ServiceAccount"
        )


def _check_namespace_deletion_protection(document: Mapping[str, Any], relative: str) -> list[str]:
    annotations = _mapping(_metadata(document).get("annotations"))
    sync_options = {
        option.strip()
        for option in str(annotations.get("argocd.argoproj.io/sync-options", "")).split(",")
    }
    errors: list[str] = []
    if "Prune=false" not in sync_options:
        errors.append(f"{relative}: namespace prune must be disabled")
    if "Delete=confirm" not in sync_options:
        errors.append(f"{relative}: namespace deletion must require confirmation")
    return errors


def check_repository(root: Path, executable: str) -> list[str]:
    errors: list[str] = []
    rendered_kustomizations: dict[str, Documents] = {}
    expected_schema_marker = _schema_migrator_contract_marker(root, errors)
    expected_octopus_checksum = _octopus_contract_checksum(root, errors)

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
        for check in (_check_otel_endpoint, _check_redpanda_memory, _check_proxy_probes, _check_proxy_wireguard_route, _check_jaeger_probes, _check_jaeger_badger_runtime, _check_atheros_search_auth, _check_atheros_search_ui_proxy, _check_keycloak_database_credential, _check_redpanda_topic_replication, _check_traefik_redirect, _check_postgres_waves, _check_postgres_plaintext_contract):
            errors.extend(check(documents, relative))
        if relative.startswith("cyber-stack/matrix/"):
            errors.extend(_check_phase_one_workload_edge(documents, relative))
            errors.extend(_check_traefik_observability(documents, relative))
            errors.extend(_check_standard_labels(documents, relative))
            errors.extend(_check_immutable_image_pulls(documents, relative))
            errors.extend(_check_ingress_policy_coverage(documents, relative))
        if relative in {
            "cyber-stack/matrix/prod",
            "cyber-stack/matrix/prod/data-plane",
        }:
            errors.extend(_check_observability_contract(documents, relative))

    errors.extend(_check_environment_identity_hostnames(rendered_kustomizations))
    environment_render_checks = {
        "cyber-stack/matrix/prod/data-plane": (
            _check_prod_alloy_positions,
            _check_prod_pgbouncer_external_postgres,
        ),
        "cyber-stack/matrix/prod/app-stack": (
            _check_prod_keycloak_external_postgres,
            _check_octopus_runtime,
        ),
        "cyber-stack/matrix/prod": (
            _check_prod_alloy_positions,
            _check_prod_pgbouncer_external_postgres,
            _check_prod_keycloak_external_postgres,
            _check_octopus_runtime,
        ),
    }
    for relative, checks in environment_render_checks.items():
        if relative not in rendered_kustomizations:
            continue
        for check in checks:
            errors.extend(check(rendered_kustomizations[relative], relative))
    if expected_octopus_checksum is not None:
        for relative in (
            "cyber-stack/matrix/prod",
            "cyber-stack/matrix/prod/app-stack",
        ):
            if relative in rendered_kustomizations:
                errors.extend(
                    _check_octopus_schema_contract(
                        rendered_kustomizations[relative],
                        relative,
                        expected_octopus_checksum,
                    )
                )
    prod_data_plane = "cyber-stack/matrix/prod/data-plane"
    if prod_data_plane in rendered_kustomizations:
        errors.extend(
            _check_prod_jaeger_recovery(
                rendered_kustomizations[prod_data_plane], prod_data_plane
            )
        )
    if expected_schema_marker is not None:
        for environment in ("prod",):
            relative = f"cyber-stack/matrix/{environment}/data-plane"
            if relative in rendered_kustomizations:
                errors.extend(_check_schema_executor_contract(rendered_kustomizations[relative], relative, expected_schema_marker))
    prod_documents = [document for component in ("bootstrap", "data-plane", "app-stack") for document in rendered_kustomizations.get(f"cyber-stack/matrix/prod/{component}", [])]
    errors.extend(_check_redpanda_topic_replication(prod_documents, "cyber-stack/matrix/prod"))
    prod_aggregate = rendered_kustomizations.get("cyber-stack/matrix/prod")
    if prod_aggregate is not None:
        try:
            platform_contract = load_platform_input_contract(root)
        except PlatformInputContractError as error:
            errors.append(str(error))
        else:
            errors.extend(compare_contract_to_rendered(platform_contract, prod_aggregate))
    errors.extend(find_committed_secret_values(root))
    if "cyber-stack/argocd-bootstrap" in rendered_kustomizations:
        _check_platform_bootstrap_application(
            rendered_kustomizations["cyber-stack/argocd-bootstrap"], errors
        )
    if "cyber-stack/argocd" in rendered_kustomizations:
        errors.extend(
            _check_phase_one_workload_edge(
                rendered_kustomizations["cyber-stack/argocd"],
                "cyber-stack/argocd",
            )
        )
        _check_application_set(rendered_kustomizations["cyber-stack/argocd"], errors)
        _check_prod_project(rendered_kustomizations["cyber-stack/argocd"], errors)
        _check_production_gate_rbac(rendered_kustomizations["cyber-stack/argocd"], errors)
        errors.extend(
            _check_default_deny_traefik(
                rendered_kustomizations["cyber-stack/argocd"],
                "cyber-stack/argocd",
            )
        )

    for environment in ("prod",):
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

    for environment in ("prod",):
        relative = Path("cyber-stack/matrix") / environment / "namespace.yaml"
        documents = _read_yaml_required(root, relative, errors, "Namespace manifest")
        if documents is None:
            continue
        namespaces = [document for document in documents if document.get("kind") == "Namespace"]
        if namespaces:
            errors.extend(_check_namespace_deletion_protection(namespaces[0], str(relative)))

    makefile = (root / "Makefile").read_text(encoding="utf-8")
    for forbidden in ("argocd-update", "release-all", "kubectl patch application"):
        if forbidden in makefile:
            errors.append(f"Makefile: live-cluster promotion surface remains: {forbidden}")
    for target in ("test", "lint", "dependency-boundaries", "atheros-search-test"):
        if re.search(rf"(?m)^{re.escape(target)}:\s*$", makefile) is None:
            errors.append(f"Makefile: documented verification target is missing: {target}")

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
