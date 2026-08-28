#!/usr/bin/env python3
"""Load and compare the value-free production platform input contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml


CONTRACT_RELATIVE_PATH = Path("cyber-stack/platform-input-contract.yaml")
CONTRACT_API_VERSION = "platform.ssl-proxy.io/v1alpha1"
CONTRACT_KIND = "PlatformInputContract"
INPUT_KINDS = ("ConfigMap", "Secret")
# Kubernetes rejects an empty Secret of type kubernetes.io/tls. The
# synchronizer replaces this pre-provisioned shell with the validated Vault TLS
# bundle before dependent workloads can start.
EMPTY_TARGET_SECRET_TYPES = {
    "pgbouncer-listener-tls": "Opaque",
}
PLATFORM_BOOTSTRAP = {
    "ownership": "platform",
    "postgres": {
        "engine": "postgresql",
        "majorVersion": 16,
        "image": (
            "pgvector/pgvector:0.8.6-pg16-bookworm@"
            "sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b"
        ),
        "endpoint": {
            "host": "192.168.1.242",
            "port": 4000,
            "database": "sync",
            "tlsMode": "verify-full",
            "tlsServerName": "192.168.1.242",
        },
        "passwordEncryption": "scram-sha-256",
        "requiredExtensions": ["pgcrypto", "vector", "pg_stat_statements"],
        "sharedPreloadLibraries": ["pg_stat_statements"],
        "persistentDataRequired": True,
    },
    "secretControlPlane": {
        "provider": "hashicorp-vault",
        "image": (
            "hashicorp/vault:1.21.4@"
            "sha256:4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569"
        ),
        "serverMode": "persistent",
        "storage": "raft",
        "tlsRequired": True,
        "developmentMode": False,
        "engine": "kv-v2",
        "mount": "secret",
    },
}


class PlatformInputContractError(ValueError):
    """Raised when the platform input contract is incomplete or unsafe."""


@dataclass(frozen=True, order=True)
class PlatformInput:
    kind: str
    name: str
    keys: tuple[str, ...]
    vault_path: str
    secret_type: str | None = None


@dataclass(frozen=True)
class PlatformInputContract:
    environment: str
    namespace: str
    inputs: tuple[PlatformInput, ...]
    document: Mapping[str, Any]

    def by_identity(self) -> dict[tuple[str, str], PlatformInput]:
        return {(entry.kind, entry.name): entry for entry in self.inputs}


@dataclass(frozen=True)
class ReferencedInput:
    kind: str
    name: str
    keys: frozenset[str]
    all_keys: bool = False


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any, label: str) -> tuple[str, ...]:
    values = _list(value)
    if not values or any(not isinstance(item, str) or not item for item in values):
        raise PlatformInputContractError(f"{label} must be a non-empty string list")
    if len(values) != len(set(values)):
        raise PlatformInputContractError(f"{label} contains duplicate keys")
    return tuple(values)


def load_platform_input_contract(root: Path) -> PlatformInputContract:
    path = root / CONTRACT_RELATIVE_PATH
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PlatformInputContractError(f"cannot read {CONTRACT_RELATIVE_PATH}: {error}") from error
    except yaml.YAMLError as error:
        raise PlatformInputContractError(f"cannot parse {CONTRACT_RELATIVE_PATH}: {error}") from error
    if not isinstance(document, Mapping):
        raise PlatformInputContractError(f"{CONTRACT_RELATIVE_PATH} must contain one mapping")
    if document.get("apiVersion") != CONTRACT_API_VERSION or document.get("kind") != CONTRACT_KIND:
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} must be {CONTRACT_API_VERSION} {CONTRACT_KIND}"
        )

    spec = _mapping(document.get("spec"))
    environment = spec.get("environment")
    namespace = spec.get("namespace")
    if environment != "prod" or namespace != "prod-ssl-proxy":
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} must target prod/prod-ssl-proxy"
        )

    bootstrap = _mapping(spec.get("bootstrap"))
    if bootstrap != PLATFORM_BOOTSTRAP:
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} must preserve the Wiretrap PostgreSQL 16/pgvector "
            "and persistent Vault bootstrap contract"
        )

    source = _mapping(spec.get("source"))
    if source != {
        "provider": "hashicorp-vault",
        "engine": "kv-v2",
        "mount": "secret",
        "pathPrefix": "secret/ssl-proxy/prod",
    }:
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} must use the production Vault KV-v2 source"
        )

    apply_policy = _mapping(spec.get("apply"))
    required_apply_policy = {
        "writerIdentity": "platform-owned",
        "validateAllKeysBeforeWrite": True,
        "idempotent": True,
        "neverLogValues": True,
    }
    if apply_policy != required_apply_policy:
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} apply policy must preserve atomic, value-safe platform ownership"
        )

    validation_policy = _mapping(spec.get("validation"))
    expected_validation_policy = {
        "identityCertificate": {
            "secretName": "ssl-proxy-identity-tls",
            "dnsName": "gateway.rclabs.uk",
        },
        "lokiHtpasswd": {
            "secretName": "observability-credentials",
            "usernameKey": "loki-username",
            "passwordKey": "loki-password",
            "htpasswdKey": "loki-htpasswd",
        },
        "postgres": {
            "endpointConfigMapName": "ssl-proxy-prod-postgres-endpoint",
            "database": "sync",
            "transport": "tls-verify-full",
            "tlsSecretName": "postgres-runtime-tls",
            "pgbouncerListenerTLSSecretName": "pgbouncer-listener-tls",
            "pgbouncerListenerTLSServerName": "postgres-pgbouncer",
            "grantMatrixDocument": "sql/postgres",
            "accounts": {
                "postgres-atheros-search": "atheros_search_runtime",
                "postgres-keycloak": "keycloak_runtime",
                "postgres-octopus": "octopus_runtime",
                "postgres-schema-migrator": "schema_migrator_runtime",
                "postgres-schema-owner": "schema_owner",
            },
        },
    }
    if validation_policy != expected_validation_policy:
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} validation policy does not preserve PostgreSQL and Loki checks"
        )

    inputs: list[PlatformInput] = []
    identities: set[tuple[str, str]] = set()
    for index, raw_input in enumerate(_list(spec.get("inputs"))):
        entry = _mapping(raw_input)
        kind = entry.get("kind")
        name = entry.get("name")
        vault_path = entry.get("vaultPath")
        label = f"{CONTRACT_RELATIVE_PATH} spec.inputs[{index}]"
        if kind not in INPUT_KINDS or not isinstance(name, str) or not name:
            raise PlatformInputContractError(f"{label} must name a Secret or ConfigMap")
        identity = (kind, name)
        if identity in identities:
            raise PlatformInputContractError(f"{label} duplicates {kind}/{name}")
        identities.add(identity)
        expected_path = f"secret/ssl-proxy/prod/{name}"
        if vault_path != expected_path:
            raise PlatformInputContractError(f"{label} vaultPath must be {expected_path}")
        keys = _strings(entry.get("keys"), f"{label}.keys")
        secret_type = entry.get("type")
        if kind == "Secret":
            if not isinstance(secret_type, str) or not secret_type:
                raise PlatformInputContractError(f"{label}.type is required for a Secret")
        elif secret_type is not None:
            raise PlatformInputContractError(f"{label}.type is only valid for a Secret")
        unexpected_fields = set(entry) - {"kind", "name", "type", "vaultPath", "keys"}
        if unexpected_fields:
            raise PlatformInputContractError(
                f"{label} contains unsupported fields: {', '.join(sorted(unexpected_fields))}"
            )
        inputs.append(PlatformInput(kind, name, keys, vault_path, secret_type))
    if not inputs:
        raise PlatformInputContractError(f"{CONTRACT_RELATIVE_PATH} has no inputs")
    tls_inputs = [
        entry
        for entry in inputs
        if entry.kind == "Secret" and entry.name == "ssl-proxy-identity-tls"
    ]
    if len(tls_inputs) != 1 or tls_inputs[0].secret_type != "kubernetes.io/tls":
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} Secret/ssl-proxy-identity-tls must use kubernetes.io/tls"
        )
    pgbouncer_tls_inputs = [
        entry
        for entry in inputs
        if entry.kind == "Secret" and entry.name == "pgbouncer-listener-tls"
    ]
    if (
        len(pgbouncer_tls_inputs) != 1
        or pgbouncer_tls_inputs[0].secret_type != "kubernetes.io/tls"
        or set(pgbouncer_tls_inputs[0].keys) != {"ca.crt", "tls.crt", "tls.key"}
    ):
        raise PlatformInputContractError(
            f"{CONTRACT_RELATIVE_PATH} Secret/pgbouncer-listener-tls must use kubernetes.io/tls with a CA, certificate, and key"
        )

    return PlatformInputContract(
        environment=str(environment),
        namespace=str(namespace),
        inputs=tuple(sorted(inputs)),
        document=document,
    )


def _pod_spec(document: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = document.get("kind")
    spec = _mapping(document.get("spec"))
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        return _mapping(_mapping(spec.get("template")).get("spec"))
    if kind == "CronJob":
        template = _mapping(
            _mapping(_mapping(spec.get("jobTemplate")).get("spec")).get("template")
        )
        return _mapping(template.get("spec"))
    if kind == "Pod":
        return spec
    return None


def _add_reference(
    references: dict[tuple[str, str], tuple[set[str], bool]],
    kind: str,
    name: Any,
    key: Any = None,
    *,
    all_keys: bool = False,
) -> None:
    if not isinstance(name, str) or not name:
        return
    keys, current_all_keys = references.setdefault((kind, name), (set(), False))
    if isinstance(key, str) and key:
        keys.add(key)
    references[(kind, name)] = (keys, current_all_keys or all_keys)


def _add_keyed_source(
    references: dict[tuple[str, str], tuple[set[str], bool]],
    kind: str,
    source: Mapping[str, Any],
    name_field: str,
) -> None:
    name = source.get(name_field)
    items = [item for item in _list(source.get("items")) if isinstance(item, Mapping)]
    if items:
        for item in items:
            _add_reference(references, kind, name, item.get("key"))
    else:
        _add_reference(references, kind, name, all_keys=True)


def inventory_referenced_inputs(
    documents: Sequence[Mapping[str, Any]],
) -> tuple[ReferencedInput, ...]:
    references: dict[tuple[str, str], tuple[set[str], bool]] = {}
    for document in documents:
        pod_spec = _pod_spec(document)
        if pod_spec is not None:
            for pull_secret in _list(pod_spec.get("imagePullSecrets")):
                _add_reference(
                    references,
                    "Secret",
                    _mapping(pull_secret).get("name"),
                    all_keys=True,
                )
            for volume in _list(pod_spec.get("volumes")):
                volume = _mapping(volume)
                secret = _mapping(volume.get("secret"))
                if secret.get("optional") is not True:
                    _add_keyed_source(references, "Secret", secret, "secretName")
                config_map = _mapping(volume.get("configMap"))
                if config_map.get("optional") is not True:
                    _add_keyed_source(references, "ConfigMap", config_map, "name")
                for source in _list(_mapping(volume.get("projected")).get("sources")):
                    source = _mapping(source)
                    projected_secret = _mapping(source.get("secret"))
                    if projected_secret.get("optional") is not True:
                        _add_keyed_source(
                            references, "Secret", projected_secret, "name"
                        )
                    projected_config_map = _mapping(source.get("configMap"))
                    if projected_config_map.get("optional") is not True:
                        _add_keyed_source(
                            references, "ConfigMap", projected_config_map, "name"
                        )
            for field in ("initContainers", "containers"):
                for container in _list(pod_spec.get(field)):
                    container = _mapping(container)
                    for env_from in _list(container.get("envFrom")):
                        env_from = _mapping(env_from)
                        secret_ref = _mapping(env_from.get("secretRef"))
                        if secret_ref.get("optional") is not True:
                            _add_reference(
                                references,
                                "Secret",
                                secret_ref.get("name"),
                                all_keys=True,
                            )
                        config_map_ref = _mapping(env_from.get("configMapRef"))
                        if config_map_ref.get("optional") is not True:
                            _add_reference(
                                references,
                                "ConfigMap",
                                config_map_ref.get("name"),
                                all_keys=True,
                            )
                    for variable in _list(container.get("env")):
                        value_from = _mapping(_mapping(variable).get("valueFrom"))
                        secret_ref = _mapping(value_from.get("secretKeyRef"))
                        if secret_ref.get("optional") is not True:
                            _add_reference(
                                references,
                                "Secret",
                                secret_ref.get("name"),
                                secret_ref.get("key"),
                            )
                        config_map_ref = _mapping(value_from.get("configMapKeyRef"))
                        if config_map_ref.get("optional") is not True:
                            _add_reference(
                                references,
                                "ConfigMap",
                                config_map_ref.get("name"),
                                config_map_ref.get("key"),
                            )
        for tls in _list(_mapping(document.get("spec")).get("tls")):
            _add_reference(
                references,
                "Secret",
                _mapping(tls).get("secretName"),
                all_keys=True,
            )
    return tuple(
        ReferencedInput(kind, name, frozenset(keys), all_keys)
        for (kind, name), (keys, all_keys) in sorted(references.items())
    )


def external_referenced_inputs(
    documents: Sequence[Mapping[str, Any]],
) -> tuple[ReferencedInput, ...]:
    rendered = {
        (str(document.get("kind")), str(_mapping(document.get("metadata")).get("name")))
        for document in documents
        if document.get("kind") in INPUT_KINDS
    }
    return tuple(
        reference
        for reference in inventory_referenced_inputs(documents)
        if (reference.kind, reference.name) not in rendered
    )


def compare_contract_to_rendered(
    contract: PlatformInputContract,
    documents: Sequence[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    contract_by_identity = contract.by_identity()
    references = {
        (reference.kind, reference.name): reference
        for reference in external_referenced_inputs(documents)
    }
    for identity in sorted(set(references) - set(contract_by_identity)):
        errors.append(f"rendered production input is undeclared: {identity[0]}/{identity[1]}")
    for identity in sorted(set(contract_by_identity) - set(references)):
        errors.append(f"platform input is not referenced by production: {identity[0]}/{identity[1]}")
    for identity in sorted(set(references) & set(contract_by_identity)):
        reference = references[identity]
        entry = contract_by_identity[identity]
        declared_keys = set(entry.keys)
        missing_declarations = sorted(set(reference.keys) - declared_keys)
        if missing_declarations:
            errors.append(
                f"{identity[0]}/{identity[1]} references undeclared keys: "
                + ", ".join(missing_declarations)
            )
        if not reference.all_keys:
            unreferenced_keys = sorted(declared_keys - set(reference.keys))
            if unreferenced_keys:
                errors.append(
                    f"{identity[0]}/{identity[1]} declares unreferenced keys: "
                    + ", ".join(unreferenced_keys)
                )
    return errors


def compare_contract_to_bootstrap(
    contract: PlatformInputContract,
    documents: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Verify the bootstrap slice owns every value-free platform input target."""

    errors: list[str] = []
    expected = contract.by_identity()
    rendered: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for document in documents:
        kind = document.get("kind")
        name = _mapping(document.get("metadata")).get("name")
        if kind in INPUT_KINDS and isinstance(name, str):
            rendered.setdefault((kind, name), []).append(document)

    for identity, entry in expected.items():
        matches = rendered.get(identity, [])
        if len(matches) != 1:
            errors.append(
                f"bootstrap must render exactly one platform input target: "
                f"{identity[0]}/{identity[1]}"
            )
            continue
        expected_type = EMPTY_TARGET_SECRET_TYPES.get(entry.name, entry.secret_type)
        if entry.kind == "Secret" and matches[0].get("type") != expected_type:
            errors.append(
                f"bootstrap Secret/{entry.name} must use type {expected_type}"
            )
    return errors


def iter_yaml_files(root: Path) -> Iterable[Path]:
    for suffix in ("*.yaml", "*.yml"):
        yield from (root / "cyber-stack").rglob(suffix)


def find_committed_secret_values(root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(set(iter_yaml_files(root))):
        relative = path.relative_to(root)
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError) as error:
            errors.append(f"{relative}: cannot inspect Secret values: {error}")
            continue
        for index, document in enumerate(documents, start=1):
            if not isinstance(document, Mapping) or document.get("kind") != "Secret":
                continue
            for field in ("data", "stringData"):
                if _mapping(document.get(field)):
                    errors.append(
                        f"{relative}: Secret document {index} contains usable {field} values"
                    )
    return errors
