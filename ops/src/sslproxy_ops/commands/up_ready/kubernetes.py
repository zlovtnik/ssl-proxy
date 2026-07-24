from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import string
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step, warn
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import peer_names, trim_key_value

HELM_PENDING_SETTLE_ATTEMPTS = 5
ROLLOUT_RESTART_KINDS = "deployments,daemonsets"


def release_fullname(ctx: UpReadyContext) -> str:
    """Return the Helm release fullname for the ssl-proxy chart."""
    release = ctx.settings.helm_release
    chart_name = "ssl-proxy"
    fullname = release if chart_name in release else f"{release}-{chart_name}"
    return fullname[:63].rstrip("-")


def proxy_workload(ctx: UpReadyContext) -> str:
    return f"deployment/{release_fullname(ctx)}-proxy"


def resolve_kube_context(ctx: UpReadyContext) -> None:
    for command in ("kubectl", "helm"):
        if shutil.which(command) is None:
            raise UpReadyError(f"Missing required command: {command}")

    configured = ctx.settings.kube_context.strip()
    completed = shell.run(
        ["kubectl", "config", "get-contexts", "-o", "name"],
        check=False,
        capture=True,
    )
    contexts = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    if configured:
        if configured in contexts:
            return
        available = ", ".join(contexts) if contexts else "none"
        raise UpReadyError(
            f"Kubernetes context {configured!r} does not exist; available contexts: {available}. "
            "Set UP_READY_KUBE_CONTEXT to a configured context name."
        )

    current = shell.run(
        ["kubectl", "config", "current-context"],
        check=False,
        capture=True,
    )
    selected = (current.stdout or "").strip()
    if current.returncode == 0 and selected:
        ctx.settings.kube_context = selected
        return

    if len(contexts) == 1:
        selected = contexts[0]
        warn(f"No current Kubernetes context was selected; using {selected!r}")
        ctx.settings.kube_context = selected
        return

    available = ", ".join(contexts) if contexts else "none"
    raise UpReadyError(
        f"No current Kubernetes context is configured; available contexts: {available}. "
        "Set UP_READY_KUBE_CONTEXT explicitly."
    )


def node_condition_problems(node: dict) -> list[str]:
    """Return human-readable problems for one node, or an empty list if healthy."""
    metadata = node.get("metadata") or {}
    name = metadata.get("name", "<unknown>")
    spec = node.get("spec") or {}
    status = node.get("status") or {}
    conditions = {
        condition.get("type"): condition.get("status")
        for condition in status.get("conditions", [])
        if isinstance(condition, dict)
    }
    problems: list[str] = []
    ready = conditions.get("Ready")
    if ready != "True":
        problems.append(f"Ready={ready or 'Unknown'}")
    for pressure in ("MemoryPressure", "DiskPressure", "PIDPressure"):
        if conditions.get(pressure) == "True":
            problems.append(f"{pressure}=True")
    if conditions.get("NetworkUnavailable") == "True":
        problems.append("NetworkUnavailable=True")
    if spec.get("unschedulable"):
        problems.append("unschedulable (cordoned)")
    return [f"{name}: {problem}" for problem in problems]


def warn_unhealthy_nodes(ctx: UpReadyContext) -> None:
    """Report node health problems without blocking the deployment."""
    completed = shell.kubectl(
        "get",
        "nodes",
        "-o",
        "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip() or "kubectl get nodes failed"
        warn(f"node health check unavailable: {detail}")
        return
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        warn("node health check unavailable: could not parse kubectl get nodes output")
        return
    nodes = payload.get("items", [])
    if not nodes:
        warn("node health check: cluster reports no nodes")
        return
    problems = [line for node in nodes for line in node_condition_problems(node)]
    if problems:
        for line in problems:
            warn(f"node health: {line}")
    else:
        step("S01", f"node health: {len(nodes)} node(s) Ready")


def kubernetes_exec(
    ctx: UpReadyContext,
    *args: str,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return shell.kubectl(
        "--namespace",
        ctx.settings.kube_namespace,
        "exec",
        proxy_workload(ctx),
        "--",
        *args,
        context=ctx.settings.kube_context,
        check=check,
        capture=capture,
    )


def kubernetes_logs(
    ctx: UpReadyContext,
    *args: str,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return shell.kubectl(
        "--namespace",
        ctx.settings.kube_namespace,
        "logs",
        *args,
        proxy_workload(ctx),
        context=ctx.settings.kube_context,
        check=check,
        capture=capture,
    )


def _apply_rendered_resource(ctx: UpReadyContext, rendered: str) -> None:
    shell.kubectl(
        "apply",
        "--server-side",
        "--field-manager=sslproxy-ops",
        "--force-conflicts",
        "-f",
        "-",
        context=ctx.settings.kube_context,
        input_text=rendered,
    )


def ensure_namespace(ctx: UpReadyContext) -> None:
    rendered = shell.kubectl(
        "create",
        "namespace",
        ctx.settings.kube_namespace,
        "--dry-run=client",
        "-o",
        "yaml",
        context=ctx.settings.kube_context,
        capture=True,
    ).stdout
    _apply_rendered_resource(ctx, rendered or "")


def apply_secret(
    ctx: UpReadyContext,
    name: str,
    files: list[tuple[str | None, Path]],
) -> None:
    command = [
        "create",
        "secret",
        "generic",
        name,
        "--namespace",
        ctx.settings.kube_namespace,
        "--dry-run=client",
        "-o",
        "yaml",
    ]
    for key, path in files:
        if not path.exists():
            raise UpReadyError(f"Missing Kubernetes Secret source: {path}")
        source = f"{key}={path}" if key else str(path)
        command.append(f"--from-file={source}")
    rendered = shell.kubectl(
        *command,
        context=ctx.settings.kube_context,
        capture=True,
    ).stdout
    _apply_rendered_resource(ctx, rendered or "")


def apply_secret_value(
    ctx: UpReadyContext,
    name: str,
    key: str,
    path: Path,
    *,
    immutable: bool = False,
) -> None:
    """Apply a file-backed Secret value without exposing it in command arguments."""
    apply_secret_values(ctx, name, [(key, path)], immutable=immutable)


def apply_secret_values(
    ctx: UpReadyContext,
    name: str,
    files: list[tuple[str, Path]],
    *,
    immutable: bool = False,
) -> None:
    """Apply newline-free scalar Secret values without exposing command arguments."""
    data: dict[str, str] = {}
    for key, path in files:
        if not path.is_file():
            raise UpReadyError(f"Missing Kubernetes Secret source: {path}")
        value = trim_key_value(path.read_text())
        if not value:
            raise UpReadyError(f"Kubernetes Secret source is empty: {path}")
        data[key] = base64.b64encode(value.encode()).decode()

    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": ctx.settings.kube_namespace,
        },
        "immutable": immutable,
        "type": "Opaque",
        "data": data,
    }
    _apply_rendered_resource(ctx, json.dumps(manifest))


def sync_kubernetes_secrets(ctx: UpReadyContext) -> bool:
    step("S02", "kubernetes_secrets: applying protected files with server-side apply")
    root = repo_root()
    secrets = root / "secrets"
    config = root / "config"
    ensure_namespace(ctx)
    apply_secret_values(
        ctx,
        "minio-credentials",
        [
            ("access-key", secrets / "minio_access_key.key"),
            ("secret-key", secrets / "minio_secret_key.key"),
        ],
    )
    apply_secret_values(ctx, "proxy-admin-key", [("api-key", secrets / "admin_api_key")])
    apply_secret_values(
        ctx,
        "proxy-runtime-secrets",
        [("wg-obfuscation-key", secrets / "wg_obfuscation_key")],
    )
    apply_secret_values(
        ctx,
        "observability-credentials",
        [("grafana-admin-password", secrets / "grafana_admin_password.key")],
    )
    apply_secret_values(
        ctx,
        "atheros-credentials",
        [("api-token-sha256", secrets / "atheros_api_token_sha256.key")],
    )
    schema_migrator_secrets = secrets / "schema-migrator"
    apply_secret_values(
        ctx,
        "schema-migrator-backend",
        [
            ("encrypt-key", schema_migrator_secrets / "encrypt_key.key"),
            ("jwt-secret", schema_migrator_secrets / "jwt_secret.key"),
            ("api-bearer-token", schema_migrator_secrets / "api_bearer_token.key"),
        ],
    )
    apply_secret_values(
        ctx,
        "schema-migrator-state-db",
        [("password", schema_migrator_secrets / "state_db_password.key")],
    )
    apply_secret_values(
        ctx,
        "schema-migrator-keycloak",
        [
            (
                "database-password",
                schema_migrator_secrets / "keycloak_database_password.key",
            ),
            (
                "bootstrap-admin-password",
                schema_migrator_secrets / "keycloak_bootstrap_admin_password.key",
            ),
        ],
    )
    apply_secret_values(
        ctx,
        "schema-migrator-bootstrap",
        [
            (
                "application-admin-password",
                schema_migrator_secrets / "application_admin_password.key",
            )
        ],
    )
    wireguard_files: list[tuple[str | None, Path]] = [
        ("server.conf", config / "templates" / "server.conf"),
        ("Corefile", config / "coredns" / "Corefile"),
        ("privatekey-server", config / "server" / "privatekey-server"),
        ("publickey-server", config / "server" / "publickey-server"),
    ]
    for peer in peer_names(os.environ.get("WG_PEERS", ctx.settings.wg_peers)):
        peer_dir = config / peer
        wireguard_files.extend(
            [
                (f"{peer}.conf", peer_dir / f"{peer}.conf"),
                (f"{peer}-obfuscated.conf", peer_dir / f"{peer}-obfuscated.conf"),
                (f"privatekey-{peer}", peer_dir / f"privatekey-{peer}"),
                (f"publickey-{peer}", peer_dir / f"publickey-{peer}"),
                (f"presharedkey-{peer}", peer_dir / f"presharedkey-{peer}"),
            ]
        )
    apply_secret(ctx, "wireguard-config", wireguard_files)
    return True


def _generate_password(length: int = 32) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _secret_exists(name: str, namespace: str, context: str | None) -> bool:
    """Check if a Kubernetes secret exists."""
    result = shell.kubectl(
        "get", "secret", name,
        "--namespace", namespace,
        "--ignore-not-found",
        context=context,
        check=False,
        capture=True,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _create_secret_from_literals(
    ctx: UpReadyContext,
    name: str,
    literals: dict[str, str],
) -> None:
    """Create a secret from literal values using kubectl."""
    command = [
        "create", "secret", "generic", name,
        "--namespace", ctx.settings.kube_namespace,
        "--dry-run=client", "-o", "yaml",
    ]
    for key, value in literals.items():
        command.append(f"--from-literal={key}={value}")
    manifest = shell.kubectl(
        *command,
        context=ctx.settings.kube_context,
        capture=True,
    ).stdout
    _apply_rendered_resource(ctx, manifest)


def sync_tidb_secrets(ctx: UpReadyContext) -> bool:
    """Generate TiDB runtime and TLS secrets if they don't exist.

    This function ensures all TiDB-related Kubernetes secrets exist before
    Helm upgrade. Runtime secrets (passwords) are only created if missing
    to preserve existing TiDB accounts. TLS secrets are always regenerated
    to support certificate rotation.
    """
    namespace = ctx.settings.kube_namespace
    context = ctx.settings.kube_context
    tidb_host = f"ssl-proxy-tidb.{namespace}.svc.cluster.local"

    # TiDB runtime secrets (only create if missing)
    if not _secret_exists("tidb-octopus", namespace, context):
        step("S02", "tidb_secrets: creating tidb-octopus")
        password = _generate_password()
        _create_secret_from_literals(ctx, "tidb-octopus", {"password": password})

    if not _secret_exists("tidb-atheros-search", namespace, context):
        step("S02", "tidb_secrets: creating tidb-atheros-search")
        password = _generate_password()
        dsn = f"atheros_search_runtime:{password}@tcp({tidb_host}:4000)/atheros_search"
        _create_secret_from_literals(ctx, "tidb-atheros-search", {"password": password, "dsn": dsn})

    if not _secret_exists("tidb-schema-migrator", namespace, context):
        step("S02", "tidb_secrets: creating tidb-schema-migrator")
        password = _generate_password()
        _create_secret_from_literals(ctx, "tidb-schema-migrator", {"password": password})

    if not _secret_exists("tidb-keycloak", namespace, context):
        step("S02", "tidb_secrets: creating tidb-keycloak")
        password = _generate_password()
        _create_secret_from_literals(ctx, "tidb-keycloak", {"password": password})

    if not _secret_exists("tidb-schema-owner", namespace, context):
        step("S02", "tidb_secrets: creating tidb-schema-owner")
        dsn = f"mysql://root@{tidb_host}:4000/"
        _create_secret_from_literals(ctx, "tidb-schema-owner", {"dsn": dsn})

    if not _secret_exists("redis-runtime", namespace, context):
        step("S02", "tidb_secrets: creating redis-runtime")
        password = _generate_password()
        _create_secret_from_literals(ctx, "redis-runtime", {"password": password})

    # TiDB TLS secrets (always regenerate)
    step("S02", "tidb_secrets: generating TiDB TLS certificates")
    with tempfile.TemporaryDirectory() as cert_dir:
        cert_path = Path(cert_dir)

        # Generate CA
        shell.run([
            "openssl", "genrsa", "-out", str(cert_path / "ca.key"), "2048"
        ], check=True, capture=True)

        # Create CA config
        ca_config = cert_path / "ca.cnf"
        ca_config.write_text("""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = TiDB Client CA

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
""")

        shell.run([
            "openssl", "req", "-new", "-x509", "-days", "3650",
            "-key", str(cert_path / "ca.key"),
            "-out", str(cert_path / "ca.crt"),
            "-config", str(ca_config),
            "-extensions", "v3_ca"
        ], check=True, capture=True)

        # Create server config
        server_config = cert_path / "tidb-server.cnf"
        server_config.write_text(f"""[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = ssl-proxy-tidb

[req_ext]
subjectAltName = @alt_names

[v3_server]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = {tidb_host}
DNS.2 = ssl-proxy-tidb
""")

        # Generate server key and CSR
        shell.run([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cert_path / "tidb-server.key"),
            "-out", str(cert_path / "tidb-server.csr"),
            "-config", str(server_config)
        ], check=True, capture=True)

        # Sign server cert with CA
        shell.run([
            "openssl", "x509", "-req", "-days", "3650",
            "-in", str(cert_path / "tidb-server.csr"),
            "-CA", str(cert_path / "ca.crt"),
            "-CAkey", str(cert_path / "ca.key"),
            "-CAcreateserial",
            "-out", str(cert_path / "tidb-server.crt"),
            "-extfile", str(server_config),
            "-extensions", "v3_server"
        ], check=True, capture=True)

        # Create tidb-client-ca secret
        ca_manifest = shell.kubectl(
            "create", "secret", "generic", "tidb-client-ca",
            "--namespace", namespace,
            f"--from-file=ca.crt={cert_path / 'ca.crt'}",
            "--dry-run=client", "-o", "yaml",
            context=context,
            capture=True,
        ).stdout
        _apply_rendered_resource(ctx, ca_manifest)

        # Create tidb-server-tls secret
        tls_manifest = shell.kubectl(
            "create", "secret", "tls", "tidb-server-tls",
            "--namespace", namespace,
            f"--cert={cert_path / 'tidb-server.crt'}",
            f"--key={cert_path / 'tidb-server.key'}",
            "--dry-run=client", "-o", "yaml",
            context=context,
            capture=True,
        ).stdout
        _apply_rendered_resource(ctx, tls_manifest)

    return True


def publish_registry_images(ctx: UpReadyContext) -> None:
    if not (
        ctx.settings.build_registry_images or ctx.settings.mirror_registry_images
    ):
        return

    registry = (ctx.settings.registry or "").strip().rstrip("/")
    if not registry:
        raise UpReadyError("REGISTRY is required to publish registry images")
    if ctx.settings.build_registry_images:
        image_tag = (ctx.settings.image_tag or "").strip()
        if not image_tag:
            raise UpReadyError("IMAGE_TAG is required to build registry images")
        step("S03", f"registry_build: first-party images -> {registry} tag={image_tag}")
        shell.run(
            [
                "make",
                "registry-build-all",
                f"REGISTRY={registry}",
                f"TAG={image_tag}",
                # The Kubernetes UI proxies /v1 to the in-cluster API. Keeping
                # this empty avoids baking a developer's localhost into it.
                "ATHEROS_SEARCH_UI_API_BASE=",
            ]
        )
    if ctx.settings.mirror_registry_images:
        step("S03", f"registry_mirror: pinned third-party images -> {registry}")
        shell.run(["make", "registry-mirror-all", f"REGISTRY={registry}"])


def verify_kubernetes_registry_pull(ctx: UpReadyContext) -> None:
    """Prove that the node runtime can pull the canonical registry reference."""
    if ctx.settings.skip_registry_preflight:
        return

    registry = os.environ["REGISTRY"].rstrip("/")
    image = f"{registry}/busybox:1.37.0"
    name = f"{ctx.settings.helm_release}-registry-pull-probe"
    namespace = ctx.settings.kube_namespace
    context = ctx.settings.kube_context
    delete_args = [
        "--namespace",
        namespace,
        "delete",
        "pod",
        name,
        "--ignore-not-found",
        "--wait=true",
    ]

    step("S03", f"kubernetes_registry_pull: image={image}")
    shell.kubectl(*delete_args, context=context, check=False, capture=True)
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": ctx.settings.helm_release,
                "app.kubernetes.io/component": "registry-pull-probe",
                "app.kubernetes.io/managed-by": "sslproxy-ops",
            },
        },
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [
                {
                    "name": "registry-pull-probe",
                    "image": image,
                    "imagePullPolicy": "Always",
                    "command": ["/bin/sh", "-c", "true"],
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "16Mi"},
                        "limits": {"cpu": "100m", "memory": "64Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "readOnlyRootFilesystem": True,
                    },
                }
            ],
        },
    }
    _apply_rendered_resource(ctx, json.dumps(manifest))
    try:
        completed = shell.kubectl(
            "--namespace",
            namespace,
            "wait",
            f"pod/{name}",
            "--for=jsonpath={.status.phase}=Succeeded",
            f"--timeout={ctx.settings.kube_registry_probe_timeout}",
            context=context,
            check=False,
            capture=True,
        )
        if completed.returncode == 0:
            return

        described = shell.kubectl(
            "--namespace",
            namespace,
            "describe",
            "pod",
            name,
            context=context,
            check=False,
            capture=True,
        )
        detail = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr, described.stdout, described.stderr)
            if part and part.strip()
        )
        raise UpReadyError(
            "Kubernetes containerd could not pull "
            f"{image} before Helm started. Configure node {ctx.settings.server_ip} for the "
            f"plain-HTTP registry {registry}, restart containerd, and retry.\n{detail}"
        )
    finally:
        shell.kubectl(*delete_args, context=context, check=False, capture=True)


def dashboard_set_file_args() -> list[str]:
    dashboards = repo_root() / "docker" / "observability" / "grafana" / "dashboards"
    names = {
        "dbCalls": "db-calls.json",
        "infraSaturation": "infra-saturation.json",
        "serviceRedMetrics": "service-red-metrics.json",
        "stackHealthOverview": "stack-health-overview.json",
        "syncPipelineLatency": "sync-pipeline-latency.json",
    }
    args: list[str] = []
    for key, filename in names.items():
        args.extend(
            ["--set-file", f"observability.grafana.dashboards.{key}={dashboards / filename}"]
        )
    args.extend(
        [
            "--set-file",
            "observability.prometheus.alertRules="
            f"{repo_root() / 'docker' / 'observability' / 'alerts.yml'}",
        ]
    )
    return args


def helm_release_status(ctx: UpReadyContext) -> str | None:
    completed = shell.helm(
        "status",
        ctx.settings.helm_release,
        "--namespace",
        ctx.settings.kube_namespace,
        "--output",
        "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if completed.returncode != 0:
        return None
    try:
        payload = json.loads(completed.stdout or "{}")
        status = payload.get("info", {}).get("status")
    except (AttributeError, TypeError, json.JSONDecodeError) as exc:
        raise UpReadyError("Unable to parse Helm release status") from exc
    if not isinstance(status, str) or not status:
        raise UpReadyError("Helm release status response did not include info.status")
    return status


def helm_release_history(ctx: UpReadyContext) -> list[dict[str, object]]:
    completed = shell.helm(
        "history",
        ctx.settings.helm_release,
        "--namespace",
        ctx.settings.kube_namespace,
        "--output",
        "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if completed.returncode != 0:
        return []
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise UpReadyError("Unable to parse Helm release history") from exc
    if not isinstance(payload, list):
        raise UpReadyError("Helm release history response was not a list")
    return [item for item in payload if isinstance(item, dict)]


def helm_pending_recovery_command(ctx: UpReadyContext) -> str:
    history = helm_release_history(ctx)
    candidates = [
        item
        for item in history
        if item.get("status") in {"deployed", "superseded"}
        and isinstance(item.get("revision"), int)
    ]
    if not candidates:
        return (
            f"helm history {ctx.settings.helm_release} "
            f"--namespace {ctx.settings.kube_namespace}"
        )
    revision = max(candidates, key=lambda item: int(item["revision"]))["revision"]
    context = (
        f" --kube-context {ctx.settings.kube_context}" if ctx.settings.kube_context else ""
    )
    return (
        f"helm{context} rollback {ctx.settings.helm_release} {revision} "
        f"--namespace {ctx.settings.kube_namespace} --no-hooks --wait=watcher "
        f"--timeout {ctx.settings.helm_timeout}"
    )


def prepare_helm_release(ctx: UpReadyContext) -> bool:
    """Return true for an upgrade, false for a clean first install."""
    status = helm_release_status(ctx)
    if status and status.startswith("pending-"):
        step(
            "S03",
            f"helm_pending: waiting for release={ctx.settings.helm_release} status={status}",
        )
        for attempt in range(HELM_PENDING_SETTLE_ATTEMPTS):
            if attempt:
                time.sleep(1)
            status = helm_release_status(ctx)
            if status is None or not status.startswith("pending-"):
                break
        if status and status.startswith("pending-"):
            step(
                "S03",
                f"helm_recover: removing stuck {status} release={ctx.settings.helm_release}",
            )
            shell.helm(
                "uninstall",
                ctx.settings.helm_release,
                "--namespace",
                ctx.settings.kube_namespace,
                "--ignore-not-found",
                "--no-hooks",
                "--cascade",
                "foreground",
                "--wait=watcher",
                "--timeout",
                ctx.settings.helm_timeout,
                context=ctx.settings.kube_context,
                capture=True,
            )
            for attempt in range(60):
                if helm_release_status(ctx) is None:
                    break
                if attempt < 59:
                    time.sleep(1)
            else:
                raise UpReadyError(
                    f"Helm release {ctx.settings.helm_release!r} still exists after cleanup"
                )
            return False
    if status is None:
        return False
    if status == "deployed":
        return True
    if status in {"failed", "uninstalled", "uninstalling"}:
        step("S03", f"helm_recover: removing {status} release={ctx.settings.helm_release}")
        shell.helm(
            "uninstall",
            ctx.settings.helm_release,
            "--namespace",
            ctx.settings.kube_namespace,
            "--ignore-not-found",
            "--no-hooks",
            "--cascade",
            "foreground",
            "--wait=watcher",
            "--timeout",
            ctx.settings.helm_timeout,
            context=ctx.settings.kube_context,
            capture=True,
        )
        for attempt in range(60):
            if helm_release_status(ctx) is None:
                return False
            if attempt < 59:
                time.sleep(1)
        raise UpReadyError(
            f"Helm release {ctx.settings.helm_release!r} still exists after cleanup"
        )
    raise UpReadyError(
        f"Helm release {ctx.settings.helm_release!r} is {status}; "
        "another Helm operation may still be active"
    )


PREFLIGHT_REQUIRED_SECRETS: dict[str, str] = {
    "redis-runtime": "password",
    "tidb-client-ca": "ca.crt",
    "tidb-octopus": "password",
    "tidb-atheros-search": "password",
    "tidb-schema-migrator": "password",
    "tidb-keycloak": "password",
    "tidb-schema-owner": "dsn",
}


def preflight_required_secrets(ctx: UpReadyContext) -> None:
    """Verify required Kubernetes Secrets exist before Helm install."""
    missing: list[str] = []
    for name, key in PREFLIGHT_REQUIRED_SECRETS.items():
        result = shell.kubectl(
            "get", "secret", name,
            "--namespace", ctx.settings.kube_namespace,
            "-o", "json",
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            missing.append(name)
            continue
        try:
            data = json.loads(result.stdout).get("data", {})
            if key not in data or not data[key]:
                missing.append(name)
        except (json.JSONDecodeError, TypeError):
            missing.append(name)
    if missing:
        raise UpReadyError(
            f"Missing {len(missing)} required Kubernetes Secret(s) in namespace "
            f"{ctx.settings.kube_namespace!r}: {', '.join(missing)}. "
            "Ensure these secrets exist before running helm install."
        )


def helm_upgrade(ctx: UpReadyContext) -> bool:
    preflight_required_secrets(ctx)
    root = repo_root()
    registry = (ctx.settings.registry or "").strip().rstrip("/")
    image_tag = (ctx.settings.image_tag or "").strip()
    if not registry:
        raise UpReadyError("REGISTRY is required for Helm deployment")
    if not image_tag:
        raise UpReadyError("IMAGE_TAG is required for Helm deployment")
    public_hostname = (ctx.settings.schema_migrator_public_hostname or "").strip()
    if not public_hostname:
        raise UpReadyError("SCHEMA_MIGRATOR_PUBLIC_HOSTNAME is required for Helm deployment")
    acme_email = (ctx.settings.acme_email or "").strip()
    if not acme_email:
        raise UpReadyError("ACME_EMAIL is required for Helm deployment")
    embedding_backend = (
        ctx.settings.atheros_search_embedding_backend
        or f"http://{ctx.settings.server_ip}:8083"
    ).strip()
    release = ctx.settings.helm_release
    namespace = ctx.settings.kube_namespace
    peers = os.environ.get("WG_PEERS", ctx.settings.wg_peers)
    values = root / "helm" / "ssl-proxy" / "values-k8s.yaml"
    chart = root / "helm" / "ssl-proxy"
    step("S03", f"helm_dependencies: refreshing chart={chart}")
    shell.helm(
        "dependency",
        "update",
        str(chart),
        context=ctx.settings.kube_context,
        capture=True,
    )
    is_upgrade = prepare_helm_release(ctx)
    literal_values = {
        "global.image.registry": registry,
        "global.rolloutRevision": ctx.run_ts,
        "proxy.image.tag": image_tag,
        "javaCoordinator.image.tag": image_tag,
        "schemaMigrator.backend.image.tag": image_tag,
        "schemaMigrator.ui.image.tag": image_tag,
        "schemaMigrator.ui.browserOrigin": f"http://{ctx.settings.server_ip}:8081",
        "schemaMigrator.publicHostname": public_hostname,
        "schemaMigrator.traefik.acme.email": acme_email,
        "schemaMigrator.keycloak.browserOrigin": f"http://{ctx.settings.server_ip}:8180",
        "schemaMigrator.keycloak.adminHostname": f"http://{ctx.settings.server_ip}:8180",
        # The backend validates `iss`; the in-cluster Keycloak issues tokens
        # from its browser-facing origin. Realm name matches the chart default
        # (schemaMigrator.keycloak.realm=middleware).
        "global.shared.keycloak.issuer": f"http://{ctx.settings.server_ip}:8180/realms/middleware",
        "atherosSensor.image.tag": image_tag,
        "atherosSearch.image.tag": image_tag,
        "atherosSearch.ui.image.tag": image_tag,
        "atherosSearch.embeddingBackend": embedding_backend,
        "proxy.wireguard.peerNames": peers,
    }
    typed_values = {
        "proxy.wireguard.port": ctx.settings.wg_port,
        "proxy.wireguard.internalPort": ctx.settings.wg_internal_port,
        "proxy.wireguard.obfuscation.enabled": str(
            ctx.settings.wg_obfuscation_enabled
        ).lower(),
    }
    args = [
        "upgrade" if is_upgrade else "install",
        release,
        str(chart),
        "--namespace",
        namespace,
        "--create-namespace",
        "--values",
        str(values),
    ]
    for key, value in literal_values.items():
        args.extend(["--set-literal", f"{key}={value}"])
    for key, value in typed_values.items():
        args.extend(["--set", f"{key}={value}"])
    args.extend(dashboard_set_file_args())
    args.extend(
        [
            "--server-side=true",
            "--wait=watcher",
            "--wait-for-jobs",
            "--timeout",
            ctx.settings.helm_timeout,
        ]
    )
    if is_upgrade:
        args.extend(["--history-max", "5", "--rollback-on-failure"])
    target = ctx.settings.kube_context or "current-context"
    operation = "upgrade" if is_upgrade else "install"
    step("S03", f"helm_{operation}: release={release} context={target}")
    shell.helm(*args, context=ctx.settings.kube_context, stream=True)
    return True


def release_workloads(ctx: UpReadyContext) -> list[str]:
    """Deployments and daemonsets owned by the Helm release.

    StatefulSets are excluded on purpose: redpanda/minio/prometheus/loki are
    data-bearing and the rolloutRevision annotation already covers their rare
    config rolls.
    """
    completed = shell.kubectl(
        "--namespace",
        ctx.settings.kube_namespace,
        "get",
        ROLLOUT_RESTART_KINDS,
        "--selector",
        f"app.kubernetes.io/instance={ctx.settings.helm_release}",
        "-o",
        "name",
        context=ctx.settings.kube_context,
        capture=True,
    )
    return [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]


def rollout_restart_release_workloads(ctx: UpReadyContext) -> None:
    """Explicitly restart and verify every release workload after a Helm upgrade.

    This makes pod pickup of freshly published mutable image tags deterministic
    instead of relying only on the rolloutRevision pod-template annotation.
    """
    workloads = release_workloads(ctx)
    if not workloads:
        warn("rollout_restart: no deployments or daemonsets found for the release")
        return
    step("S03", f"rollout_restart: {' '.join(workloads)}")
    shell.kubectl(
        "--namespace",
        ctx.settings.kube_namespace,
        "rollout",
        "restart",
        *workloads,
        context=ctx.settings.kube_context,
        capture=True,
    )
    for workload in workloads:
        step("S03", f"rollout_status: {workload}")
        shell.kubectl(
            "--namespace",
            ctx.settings.kube_namespace,
            "rollout",
            "status",
            workload,
            f"--timeout={ctx.settings.rollout_status_timeout}",
            context=ctx.settings.kube_context,
            capture=True,
        )


def _statefulset_exists(ctx: UpReadyContext, name: str) -> bool:
    result = shell.kubectl(
        "get", "statefulset", name,
        "--namespace", ctx.settings.kube_namespace,
        "--ignore-not-found",
        context=ctx.settings.kube_context,
        capture=True,
    )
    return bool((result.stdout or "").strip())


def apply_raw_tidb_manifests(ctx: UpReadyContext) -> None:
    step("S02", "tidb_manifests: applying raw TiDB namespace, service, configmap, and statefulset")
    root = repo_root()
    for filename in ("namespace.yaml", "service.yaml", "configmap.yaml", "statefulset.yaml"):
        path = root / "k8s" / "tidb" / filename
        if not path.exists():
            raise UpReadyError(f"Missing TiDB manifest: {path}")
        _apply_rendered_resource(ctx, path.read_text())


def apply_tidb_init_job(ctx: UpReadyContext) -> None:
    try:
        result = shell.kubectl(
            "get", "job", "ssl-proxy-tidb-init",
            "--namespace", ctx.settings.kube_namespace,
            "-o", "jsonpath={.status.succeeded}|{.status.active}|{.status.failed}",
            context=ctx.settings.kube_context,
            capture=True,
        )
    except shell.ShellCommandError as e:
        if e.returncode == 1 and "NotFound" in e.stderr:
            pass
        else:
            raise
    else:
        parts = (result.stdout or "").strip().split("|")
        succeeded = parts[0] if len(parts) > 0 and parts[0] else ""
        active = parts[1] if len(parts) > 1 and parts[1] else ""
        failed = parts[2] if len(parts) > 2 and parts[2] else ""

        if succeeded == "1":
            warn("tidb_init_job: ssl-proxy-tidb-init already completed; skipping")
            return
        if active and int(active) > 0:
            warn("tidb_init_job: ssl-proxy-tidb-init is active; skipping")
            return
        if failed and int(failed) > 0:
            warn("tidb_init_job: ssl-proxy-tidb-init failed; deleting for retry")
            shell.kubectl(
                "delete", "job", "ssl-proxy-tidb-init",
                "--namespace", ctx.settings.kube_namespace,
                context=ctx.settings.kube_context,
                capture=True,
            )

    step("S02", "tidb_init_job: applying database/user bootstrap job")
    root = repo_root()
    path = root / "k8s" / "tidb" / "init-job.yaml"
    if not path.exists():
        raise UpReadyError(f"Missing TiDB init job manifest: {path}")
    _apply_rendered_resource(ctx, path.read_text())
    step("S02", "tidb_init_job: waiting for ssl-proxy-tidb-init to complete")
    shell.kubectl(
        "--namespace", ctx.settings.kube_namespace,
        "wait", "--for=condition=complete", "job/ssl-proxy-tidb-init",
        f"--timeout={ctx.settings.rollout_status_timeout}",
        context=ctx.settings.kube_context,
        capture=True,
    )


def ensure_tidb_ready(ctx: UpReadyContext) -> None:
    """Ensure TiDB is running with current TLS certificates.

    On a fresh install, applies raw manifests and waits for the StatefulSet.
    On an existing install, rolls it out to pick up regenerated certs.
    """
    if _statefulset_exists(ctx, "ssl-proxy-tidb"):
        step("S02", "restart_tidb: restarting ssl-proxy-tidb for TLS cert rotation")
        shell.kubectl(
            "--namespace", ctx.settings.kube_namespace,
            "rollout", "restart", "statefulset/ssl-proxy-tidb",
            context=ctx.settings.kube_context,
            capture=True,
        )
    else:
        step("S02", "tidb_fresh_install: applying raw TiDB manifests")
        apply_raw_tidb_manifests(ctx)

    shell.kubectl(
        "--namespace", ctx.settings.kube_namespace,
        "rollout", "status", "statefulset/ssl-proxy-tidb",
        f"--timeout={ctx.settings.rollout_status_timeout}",
        context=ctx.settings.kube_context,
        capture=True,
    )


def kubernetes_up(ctx: UpReadyContext) -> bool:
    try:
        sync_kubernetes_secrets(ctx)
        sync_tidb_secrets(ctx)
        ensure_tidb_ready(ctx)
        apply_tidb_init_job(ctx)
        publish_registry_images(ctx)
        verify_kubernetes_registry_pull(ctx)
        helm_upgrade(ctx)
        rollout_restart_release_workloads(ctx)
    except (shell.ShellCommandError, UpReadyError) as exc:
        ctx.classify(str(exc))
        return False
    return True


def recent_kubernetes_warning_lines(ctx: UpReadyContext) -> list[str]:
    events = shell.kubectl(
        "--namespace",
        ctx.settings.kube_namespace,
        "get",
        "events",
        "--field-selector=type=Warning",
        "-o",
        "json",
        context=ctx.settings.kube_context,
        check=False,
        capture=True,
    )
    if events.returncode != 0:
        return []
    try:
        payload = json.loads(events.stdout or "{}")
        run_started = datetime.fromisoformat(ctx.run_ts)
        recent: list[tuple[datetime, str]] = []
        for event in payload.get("items", []):
            if not isinstance(event, dict):
                continue
            series = event.get("series") or {}
            metadata = event.get("metadata") or {}
            timestamp = (
                event.get("eventTime")
                or series.get("lastObservedTime")
                or event.get("lastTimestamp")
                or metadata.get("creationTimestamp")
            )
            if not isinstance(timestamp, str):
                continue
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed < run_started:
                continue
            involved = event.get("involvedObject") or {}
            target = f"{involved.get('kind', 'Object')}/{involved.get('name', 'unknown')}"
            line = (
                f"{parsed.isoformat()} {event.get('reason', 'Warning')} "
                f"{target}: {event.get('message', '')}"
            )
            recent.append((parsed, line))
        return [line for _timestamp, line in sorted(recent, key=lambda item: item[0])[-40:]]
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return []


def print_classified_failure(ctx: UpReadyContext) -> None:
    print("--- classified failure ---")
    print(f"class={ctx.last_failure.name}")
    print(f"cause={ctx.last_failure.cause}")
    print(f"fix={ctx.last_failure.fix}")
    print(f"retry={ctx.last_failure.retry}")


def kubernetes_diagnostics(ctx: UpReadyContext) -> None:
    namespace = ctx.settings.kube_namespace
    context = ctx.settings.kube_context
    try:
        release_status = helm_release_status(ctx) or "not-found"
    except UpReadyError as exc:
        release_status = f"unknown ({exc})"
    warning_lines = recent_kubernetes_warning_lines(ctx)
    evidence = "\n".join([ctx.last_failure_text, *warning_lines])
    ctx.classify(evidence)
    print("--- deployment failure ---")
    print(ctx.last_failure_text or ctx.last_failure.cause)
    print(f"helm_release_status={release_status}")
    print_classified_failure(ctx)
    shell.kubectl(
        "--namespace", namespace, "get", "pods", "-o", "wide", context=context, check=False
    )
    print("--- Kubernetes warning events from this run ---")
    if warning_lines:
        print("\n".join(warning_lines))
    else:
        print("none")

    workload = shell.kubectl(
        "--namespace",
        namespace,
        "get",
        proxy_workload(ctx),
        "-o",
        "name",
        context=context,
        check=False,
        capture=True,
    )
    if workload.returncode == 0:
        shell.kubectl(
            "--namespace",
            namespace,
            "logs",
            "--tail",
            str(ctx.settings.log_tail_lines),
            proxy_workload(ctx),
            context=context,
            check=False,
        )
