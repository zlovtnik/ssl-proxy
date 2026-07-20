from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step, warn
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import peer_names, trim_key_value

HELM_PENDING_SETTLE_ATTEMPTS = 5


def proxy_workload(ctx: UpReadyContext) -> str:
    release = ctx.settings.helm_release
    chart_name = "ssl-proxy"
    fullname = release if chart_name in release else f"{release}-{chart_name}"
    return f"deployment/{fullname[:63].rstrip('-')}-proxy"


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
    # postgres.key is generated once and is the durable credential authority. Store the
    # same newline-free value used by .env and the operator credential handoff, then make
    # the Kubernetes Secret immutable so routine upgrades cannot rotate it accidentally.
    apply_secret_value(
        ctx,
        "postgres-credentials",
        "password",
        secrets / "postgres.key",
        immutable=True,
    )
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
        "integrationConsoleHealth": "integration-console-health.json",
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
            "--set-file",
            "observability.postgresExporter.queries="
            f"{repo_root() / 'docker' / 'observability' / 'postgres-exporter-queries.yml'}",
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
            recovery = helm_pending_recovery_command(ctx)
            raise UpReadyError(
                f"Helm release {ctx.settings.helm_release!r} remains {status}; "
                f"recover it before rerunning up-ready: {recovery}"
            )
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


def helm_upgrade(ctx: UpReadyContext) -> bool:
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
        "integrationConsole.web.image.tag": image_tag,
        "integrationConsole.dbSetup.image.tag": image_tag,
        "schemaMigrator.backend.image.tag": image_tag,
        "schemaMigrator.ui.image.tag": image_tag,
        "schemaMigrator.ui.browserOrigin": f"http://{ctx.settings.server_ip}:8081",
        "schemaMigrator.publicHostname": public_hostname,
        "schemaMigrator.traefik.acme.email": acme_email,
        "schemaMigrator.keycloak.browserOrigin": f"http://{ctx.settings.server_ip}:8180",
        "schemaMigrator.keycloak.adminHostname": f"http://{ctx.settings.server_ip}:8180",
        "atherosSensor.image.tag": image_tag,
        "atherosSearch.image.tag": image_tag,
        "atherosSearch.ui.image.tag": image_tag,
        "atherosSearch.embeddingBackend": embedding_backend,
        "postgres.image.tag": image_tag,
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
    completed = shell.helm(*args, context=ctx.settings.kube_context, capture=True)
    if isinstance(completed.stdout, str) and completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if isinstance(completed.stderr, str) and completed.stderr:
        print(
            completed.stderr,
            end="" if completed.stderr.endswith("\n") else "\n",
            file=__import__("sys").stderr,
        )
    return True


def kubernetes_up(ctx: UpReadyContext) -> bool:
    try:
        sync_kubernetes_secrets(ctx)
        publish_registry_images(ctx)
        verify_kubernetes_registry_pull(ctx)
        helm_upgrade(ctx)
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
