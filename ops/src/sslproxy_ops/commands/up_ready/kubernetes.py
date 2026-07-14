from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import peer_names


def proxy_workload(ctx: UpReadyContext) -> str:
    return f"deployment/{ctx.settings.helm_release}-proxy"


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


def sync_kubernetes_secrets(ctx: UpReadyContext) -> None:
    step("S02", "kubernetes_secrets: applying protected files with server-side apply")
    root = repo_root()
    secrets = root / "secrets"
    config = root / "config"
    ensure_namespace(ctx)
    apply_secret(ctx, "postgres-credentials", [("password", secrets / "postgres.key")])
    apply_secret(
        ctx,
        "minio-credentials",
        [
            ("access-key", secrets / "minio_access_key.key"),
            ("secret-key", secrets / "minio_secret_key.key"),
        ],
    )
    apply_secret(ctx, "proxy-admin-key", [("api-key", secrets / "admin_api_key")])
    apply_secret(
        ctx,
        "proxy-runtime-secrets",
        [("wg-obfuscation-key", secrets / "wg_obfuscation_key")],
    )
    apply_secret(
        ctx,
        "observability-credentials",
        [("grafana-admin-password", secrets / "grafana_admin_password.key")],
    )
    apply_secret(
        ctx,
        "atheros-credentials",
        [("api-token-sha256", secrets / "atheros_api_token_sha256.key")],
    )
    apply_secret(ctx, "oracle-credentials", [("password", secrets / "oracle_password.txt")])
    apply_secret(ctx, "oracle-wallet", [(None, root / "wallet")])

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


def publish_registry_images(ctx: UpReadyContext) -> None:
    registry = os.environ["REGISTRY"]
    image_tag = os.environ["IMAGE_TAG"]
    common = [f"REGISTRY={registry}", f"TAG={image_tag}"]
    if ctx.settings.build_registry_images:
        step("S03", f"registry_build: first-party images -> {registry} tag={image_tag}")
        shell.run(["make", "registry-build-all", *common])
    if ctx.settings.mirror_registry_images:
        step("S03", f"registry_mirror: pinned third-party images -> {registry}")
        shell.run(["make", "registry-mirror-all", *common])


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


def helm_upgrade(ctx: UpReadyContext) -> None:
    root = repo_root()
    registry = os.environ["REGISTRY"].rstrip("/")
    image_tag = os.environ["IMAGE_TAG"]
    release = ctx.settings.helm_release
    namespace = ctx.settings.kube_namespace
    peers = os.environ.get("WG_PEERS", ctx.settings.wg_peers)
    values = root / "helm" / "ssl-proxy" / "values-microk8s.yaml"
    chart = root / "helm" / "ssl-proxy"
    set_values = {
        "global.image.registry": registry,
        "proxy.image.tag": image_tag,
        "javaCoordinator.image.tag": image_tag,
        "integrationConsole.web.image.tag": image_tag,
        "integrationConsole.dbSetup.image.tag": image_tag,
        "atherosSensor.image.tag": image_tag,
        "atherosSearch.image.tag": image_tag,
        "postgres.image.tag": image_tag,
        "proxy.wireguard.peerNames": peers,
        "proxy.wireguard.port": os.environ["WG_PORT"],
        "proxy.wireguard.internalPort": os.environ["WG_INTERNAL_PORT"],
        "proxy.wireguard.obfuscation.enabled": os.environ["WG_OBFUSCATION_ENABLED"],
        "proxy.service.externalIPs[0]": ctx.settings.server_ip,
        "integrationConsole.web.service.externalIPs[0]": ctx.settings.server_ip,
        "observability.grafana.service.externalIPs[0]": ctx.settings.server_ip,
        "observability.jaeger.service.externalIPs[0]": ctx.settings.server_ip,
    }
    args = [
        "upgrade",
        "--install",
        release,
        str(chart),
        "--namespace",
        namespace,
        "--create-namespace",
        "--values",
        str(values),
    ]
    for key, value in set_values.items():
        args.extend(["--set-string", f"{key}={value}"])
    args.extend(dashboard_set_file_args())
    args.extend(["--rollback-on-failure", "--wait", "--timeout", ctx.settings.helm_timeout])
    step("S03", f"helm_upgrade: release={release} context={ctx.settings.kube_context}")
    shell.helm(*args, context=ctx.settings.kube_context)


def kubernetes_up(ctx: UpReadyContext) -> bool:
    try:
        sync_kubernetes_secrets(ctx)
        publish_registry_images(ctx)
        helm_upgrade(ctx)
    except (shell.ShellCommandError, UpReadyError) as exc:
        ctx.classify(str(exc))
        return False
    return True


def kubernetes_diagnostics(ctx: UpReadyContext) -> None:
    namespace = ctx.settings.kube_namespace
    context = ctx.settings.kube_context
    shell.kubectl("--namespace", namespace, "get", "pods", "-o", "wide", context=context, check=False)
    shell.kubectl(
        "--namespace",
        namespace,
        "get",
        "events",
        "--sort-by=.lastTimestamp",
        context=context,
        check=False,
    )
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
