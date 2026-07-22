from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path

import httpx

from sslproxy_ops import shell
from sslproxy_ops.commands.memo import insert_incident
from sslproxy_ops.commands.up_ready.kubernetes import (
    kubernetes_diagnostics,
    kubernetes_exec,
    kubernetes_logs,
    release_fullname,
)
from sslproxy_ops.commands.up_ready.model import (
    UpReadyContext,
    UpReadyError,
    desired_obfuscation_value,
    step,
    warn,
)
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import peer_names, trim_key_value
from sslproxy_ops.util.qr import render_qr_file, render_qr_text


def proxy_exec(
    ctx: UpReadyContext,
    *args: str,
    check: bool = True,
    capture: bool = False,
):
    if ctx.settings.deployment_target == "kubernetes":
        return kubernetes_exec(ctx, *args, check=check, capture=capture)
    return shell.compose(
        "exec",
        "-T",
        ctx.settings.service_name,
        *args,
        check=check,
        capture=capture,
    )


def proxy_logs(
    ctx: UpReadyContext,
    *args: str,
    check: bool = True,
    capture: bool = False,
):
    if ctx.settings.deployment_target == "kubernetes":
        return kubernetes_logs(ctx, *args, check=check, capture=capture)
    return shell.compose(
        "logs",
        *args,
        ctx.settings.service_name,
        check=check,
        capture=capture,
    )


def wait_for_kubernetes_stack(ctx: UpReadyContext) -> bool:
    deadline = time.monotonic() + ctx.settings.health_timeout_secs
    while time.monotonic() < deadline:
        completed = shell.kubectl(
            "--namespace",
            ctx.settings.kube_namespace,
            "get",
            "pods",
            "--selector",
            f"app.kubernetes.io/instance={ctx.settings.helm_release}",
            "-o",
            "json",
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        )
        if completed.returncode == 0:
            pods = json.loads(completed.stdout or "{}").get("items", [])
            active = [pod for pod in pods if pod.get("status", {}).get("phase") != "Succeeded"]
            if active and all(
                pod.get("status", {}).get("phase") == "Running"
                and all(
                    status.get("ready")
                    for status in pod.get("status", {}).get("containerStatuses", [])
                )
                for pod in active
            ):
                return True
        time.sleep(1)
    return False


def wait_for_container_healthy(ctx: UpReadyContext, service: str) -> bool:
    deadline = time.monotonic() + ctx.settings.health_timeout_secs
    while time.monotonic() < deadline:
        cid = (shell.compose("ps", "-q", service, check=False, capture=True).stdout or "").strip()
        if cid:
            status = (
                shell.run(
                    ["docker", "inspect", "-f", "{{.State.Status}}", cid],
                    check=False,
                    capture=True,
                ).stdout
                or ""
            ).strip()
            health = (
                shell.run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                        cid,
                    ],
                    check=False,
                    capture=True,
                ).stdout
                or ""
            ).strip()
            if status == "running" and health in {"healthy", "none"}:
                return True
        time.sleep(1)
    return False


def kubernetes_service_exists(ctx: UpReadyContext, service: str) -> bool:
    return (
        shell.kubectl(
            "--namespace",
            ctx.settings.kube_namespace,
            "get",
            "service",
            service,
            context=ctx.settings.kube_context,
            check=False,
            capture=True,
        ).returncode
        == 0
    )


def check_cluster_http(ctx: UpReadyContext, url: str) -> bool:
    """HTTP GET an in-cluster Service URL via curl in the proxy pod."""
    return (
        kubernetes_exec(
            ctx,
            "curl",
            "-fsS",
            "--max-time",
            "5",
            url,
            check=False,
            capture=True,
        ).returncode
        == 0
    )


def kubernetes_component_health_endpoints(ctx: UpReadyContext) -> list[tuple[str, str, str]]:
    """(label, service, health URL) tuples for first-party HTTP health checks."""
    fullname = release_fullname(ctx)
    return [
        (
            "java_coordinator_health",
            f"{fullname}-coordinator",
            f"http://{fullname}-coordinator:8080/actuator/health",
        ),
        (
            "schema_migrator_backend_health",
            f"{fullname}-schema-migrator-backend",
            f"http://{fullname}-schema-migrator-backend:8080/api/health",
        ),
        (
            "schema_migrator_keycloak_health",
            f"{fullname}-schema-migrator-keycloak",
            f"http://{fullname}-schema-migrator-keycloak:8080/health/ready",
        ),
    ]


def verify_component_health(ctx: UpReadyContext) -> bool:
    """Verify schema-migrator backend, coordinator, and keycloak health endpoints.

    Components whose Service is absent (for example a disabled subchart) are
    skipped; present components must answer their health endpoint.
    """
    for label, service, url in kubernetes_component_health_endpoints(ctx):
        if not kubernetes_service_exists(ctx, service):
            step("S04", f"{label}: service {service} absent; skipping")
            continue
        if not run_check_with_retry(ctx, label, lambda url=url: check_cluster_http(ctx, url)):
            ctx.classify(f"{label} failed: {url} did not return a successful response")
            return False
    return True


def classify_service_failure(ctx: UpReadyContext, service: str) -> None:
    logs = shell.compose(
        "logs", "--tail", str(ctx.settings.log_tail_lines), service, check=False, capture=True
    )
    suffix = {
        "java-coordinator": "java-coordinator unhealthy",
        "redpanda": "redpanda unhealthy",
    }.get(service, f"{service} unhealthy")
    ctx.classify(f"{logs.stdout}\n{logs.stderr}\n{suffix}")


def run_check_with_retry(ctx: UpReadyContext, label: str, fn) -> bool:
    deadline = time.monotonic() + ctx.settings.check_retry_secs
    while True:
        if fn():
            return True
        if time.monotonic() >= deadline:
            ctx.last_failed_check = label
            return False
        time.sleep(1)


def check_admin_health(ctx: UpReadyContext) -> bool:
    try:
        response = httpx.get("http://127.0.0.1:3002/health", timeout=2.0)
        if 200 <= response.status_code < 300:
            return True
    except httpx.HTTPError:
        pass
    if (
        proxy_exec(
            ctx,
            "curl",
            "-fsS",
            "--max-time",
            "2",
            "http://127.0.0.1:3002/health",
            check=False,
            capture=True,
        ).returncode
        == 0
    ):
        warn("Host-local admin check failed, but in-container admin health is OK")
        return True
    return False


def health_checks(ctx: UpReadyContext) -> bool:
    step("S04", "health_checks: stack + admin + ready")
    ctx.last_failed_check = ""
    if ctx.settings.deployment_target == "kubernetes":
        if not wait_for_kubernetes_stack(ctx):
            ctx.last_failed_check = "kubernetes_stack_health"
            ctx.classify("Kubernetes stack did not become Ready before the health timeout")
            return False
        if not verify_component_health(ctx):
            return False
    else:
        for service in ctx.settings.stack_health_service_names:
            if not wait_for_container_healthy(ctx, service):
                ctx.last_failed_check = f"{service}_health"
                classify_service_failure(ctx, service)
                return False
    if not run_check_with_retry(ctx, "admin_health", lambda: check_admin_health(ctx)):
        return False
    body = ""
    code = "000"
    try:
        response = httpx.get("http://127.0.0.1:3002/ready", timeout=2.0)
        code = str(response.status_code)
        body = response.text.replace("\n", "")
    except httpx.HTTPError:
        pass
    if code == "000":
        completed = proxy_exec(
            ctx,
            "curl",
            "-sS",
            "-o",
            "/tmp/up-ready-ready-body.txt",
            "-w",
            "%{http_code}",
            "--max-time",
            "2",
            "http://127.0.0.1:3002/ready",
            check=False,
            capture=True,
        )
        code = (completed.stdout or "").strip()
        body = (
            proxy_exec(
                ctx,
                "sh",
                "-lc",
                "cat /tmp/up-ready-ready-body.txt",
                check=False,
                capture=True,
            ).stdout
            or ""
        ).replace("\n", "")
    if code == "200":
        step("S04", "ready endpoint: 200")
    else:
        warn(f"ready endpoint: {code} (non-blocking) {body}")
    return True


def runtime_obfuscation_value(ctx_or_service: UpReadyContext | str) -> str:
    if isinstance(ctx_or_service, str):
        logs = shell.compose("logs", "--tail", "200", ctx_or_service, check=False, capture=True)
    else:
        logs = proxy_logs(ctx_or_service, "--tail", "200", check=False, capture=True)
    matches = re.findall(r"wg_obfuscation_enabled=(true|false)", logs.stdout or "")
    return matches[-1] if matches else ""


def check_udp_listener(ctx: UpReadyContext, port: int) -> bool:
    return (
        proxy_exec(
            ctx,
            "sh",
            "-lc",
            f"ss -H -lun '( sport = :{port} )' | grep -q .",
            check=False,
            capture=True,
        ).returncode
        == 0
    )


def check_frontdoor_udp_listener(ctx: UpReadyContext, port: int) -> bool:
    return (
        shell.compose(
            "exec",
            "-T",
            ctx.settings.frontdoor_service_name,
            "sh",
            "-lc",
            f"ss -H -lun '( sport = :{port} )' | grep -q .",
            check=False,
            capture=True,
        ).returncode
        == 0
    )


def check_tcp_listener(ctx: UpReadyContext, port: int) -> bool:
    return (
        proxy_exec(
            ctx,
            "sh",
            "-lc",
            f"ss -H -ltn '( sport = :{port} )' | grep -q .",
            check=False,
            capture=True,
        ).returncode
        == 0
    )


def network_checks(ctx: UpReadyContext) -> bool:
    step("S05", "network_checks: wg/listeners")

    def boringtun() -> bool:
        return (
            proxy_exec(
                ctx,
                "/app/ssl-proxy",
                "boringtun",
                "show",
                "wg0",
                check=False,
                capture=True,
            ).returncode
            == 0
        )

    if not run_check_with_retry(ctx, "wg_interface", boringtun):
        return False
    for label, fn in [
        ("udp_443", lambda: check_udp_listener(ctx, 443)),
        ("udp_53", lambda: check_udp_listener(ctx, 53)),
        ("tcp_3001", lambda: check_tcp_listener(ctx, 3001)),
        ("tcp_3002", lambda: check_tcp_listener(ctx, 3002)),
    ]:
        if not run_check_with_retry(ctx, label, fn):
            return False
    if runtime_obfuscation_value(ctx) == "true" and not run_check_with_retry(
        ctx, "udp_51820", lambda: check_udp_listener(ctx, 51820)
    ):
        return False
    if ctx.settings.deployment_target == "compose":
        for label, port in [("frontdoor_udp_443", 443), ("frontdoor_udp_51820", 51820)]:
            if not run_check_with_retry(
                ctx,
                label,
                lambda port=port: check_frontdoor_udp_listener(ctx, port),
            ):
                return False
    return True


def mode_guardrails(ctx: UpReadyContext) -> bool:
    profile = ctx.settings.profile_mode
    step(
        "S02",
        f"mode_guardrails: PROFILE_MODE={profile} SERVER_IP={ctx.settings.server_ip} "
        f"CLIENT_IP={ctx.settings.client_ip} arch={ctx.host_arch}",
    )
    expected = desired_obfuscation_value(str(ctx.settings.profile_mode))
    actual = runtime_obfuscation_value(ctx)
    if not actual:
        warn("Could not read runtime obfuscation from logs yet; proceeding")
        return True
    if actual != expected:
        ctx.last_failed_check = "mode_guardrails"
        ctx.classify(
            f"profile mismatch: expected obfuscation={expected} actual={actual} "
            f"wg_obfuscation_enabled={actual}"
        )
        return False
    if ctx.settings.profile_mode == "iphone":
        warn("iPhone mode: do not use local shim endpoint 127.0.0.1:51821 in iPhone profile")
    return True


def peer_checks(ctx: UpReadyContext) -> bool:
    step("S06", "peer_checks: snapshot")
    completed = proxy_exec(
        ctx,
        "/app/ssl-proxy",
        "boringtun",
        "dump",
        "wg0",
        check=False,
        capture=True,
    )
    snapshot = f"{completed.stdout or ''}{completed.stderr or ''}"
    print(snapshot)
    for idx, line in enumerate(snapshot.splitlines()):
        if idx == 0:
            continue
        fields = line.split()
        if len(fields) >= 5:
            try:
                if int(fields[4]) > 0:
                    step("S06", "peer handshake present")
                    return True
            except ValueError:
                pass
    warn("No peer handshake yet. Toggle client tunnel and re-check")
    return False


def discover_peer_configs(ctx: UpReadyContext) -> None:
    for peer_dir in sorted((repo_root() / "config").glob("*")):
        if not peer_dir.is_dir() or peer_dir.name in {"coredns", "templates", "client", "server"}:
            continue
        key_files = sorted(peer_dir.glob("publickey-*"))
        if not key_files:
            continue
        key = trim_key_value(key_files[0].read_text())
        if not key:
            continue
        obfuscated = sorted(peer_dir.glob("*obfuscated*.conf*"))
        fallback = [
            path for path in sorted(peer_dir.glob("*.conf")) if "obfuscated" not in path.name
        ]
        selected: Path | None = None
        if ctx.settings.profile_mode in {"iphone", "linux-direct"}:
            if not fallback and obfuscated:
                raise UpReadyError(
                    f"Direct client mode requires a non-obfuscated WireGuard profile in {peer_dir}"
                )
            selected = fallback[0] if fallback else None
        else:
            selected = obfuscated[0] if obfuscated else (fallback[0] if fallback else None)
        if selected:
            ctx.peer_configs[key] = str(selected)


def to_container_config_path(path: Path) -> str | None:
    try:
        relative = path.relative_to(repo_root() / "config")
    except ValueError:
        return None
    return f"/config/{relative}"


def print_qr_for_config(ctx: UpReadyContext, cfg: Path) -> None:
    if os.access(cfg, os.R_OK):
        render_qr_file(cfg, qr_type=ctx.settings.qr_type, margin=ctx.settings.qr_margin)
        return
    container_cfg = to_container_config_path(cfg)
    if container_cfg:
        test = proxy_exec(
            ctx,
            "test",
            "-r",
            container_cfg,
            check=False,
            capture=True,
        )
        if test.returncode == 0:
            text = (
                proxy_exec(
                    ctx,
                    "cat",
                    container_cfg,
                    capture=True,
                ).stdout
                or ""
            )
            render_qr_text(text, qr_type=ctx.settings.qr_type, margin=ctx.settings.qr_margin)
            return
    raise UpReadyError(f"QR render failed for config: {cfg}")


def qr_render(ctx: UpReadyContext) -> bool:
    step("S07", "qr_render: real peers")
    completed = proxy_exec(
        ctx,
        "/app/ssl-proxy",
        "boringtun",
        "dump",
        "wg0",
        check=False,
        capture=True,
    )
    peers: list[str] = []
    seen: set[str] = set()
    for idx, line in enumerate((completed.stdout or "").splitlines()):
        if idx == 0:
            continue
        fields = line.split()
        if fields and fields[0] not in seen:
            seen.add(fields[0])
            peers.append(fields[0])
    if not peers:
        warn("No peers listed in wg dump")
        return True
    failures = 0
    for peer_key in peers:
        cfg = ctx.peer_configs.get(peer_key)
        if not cfg:
            warn(f"No local config mapping for peer key: {peer_key}")
            continue
        print(f"\n=== Peer {peer_key} ===\nConfig: {cfg}")
        try:
            print_qr_for_config(ctx, Path(cfg))
        except UpReadyError:
            warn(f"QR render failed for config: {cfg}")
            ctx.classify(f"Permission denied while QR rendering {cfg}")
            failures += 1
    return failures == 0


def append_file_section(output: Path, title: str, path: Path) -> None:
    with output.open("a") as handle:
        if path.is_file() and path.stat().st_size > 0:
            handle.write(f"\n## {title}\n")
            handle.write(f"path={path}\n\n")
            handle.write(path.read_text(errors="ignore"))
            handle.write("\n")
        else:
            handle.write(f"\n## {title}\n")
            handle.write(f"missing={path}\n")


def read_handoff_secret(path: Path) -> str:
    return trim_key_value(path.read_text()) if path.is_file() and path.stat().st_size > 0 else ""


def write_credential_handoff(ctx: UpReadyContext) -> None:
    step("S09", "credential_handoff")
    output = ctx.settings.credential_handoff_file
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f"{output.name}.", dir=output.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    grafana_password = read_handoff_secret(repo_root() / "secrets" / "grafana_admin_password.key")
    admin_api_key = read_handoff_secret(repo_root() / "secrets" / "admin_api_key")
    wg_obfuscation_key = read_handoff_secret(repo_root() / "secrets" / "wg_obfuscation_key")
    schema_admin_password = read_handoff_secret(
        repo_root() / "secrets" / "schema-migrator" / "application_admin_password.key"
    )
    with tmp.open("w") as handle:
        handle.write("# ssl-proxy credential handoff\n")
        handle.write(f"generated_at={ctx.run_ts}\n")
        handle.write(f"profile_mode={ctx.settings.profile_mode}\n")
        handle.write(f"server_ip={ctx.settings.server_ip}\n")
        handle.write(f"client_ip={ctx.settings.client_ip}\n")
        handle.write("\n## Proxy admin API\n")
        handle.write("url=http://127.0.0.1:3002\n")
        handle.write(f"admin_api_key={admin_api_key}\n")
        if ctx.settings.profile_mode in {"linux-shim", "mac"}:
            wg_public_port = os.getenv("WG_PORT", "443")
            handle.write("\n## WireGuard shim\n")
            handle.write("enabled=true\n")
            handle.write(f"shim_pass={wg_obfuscation_key}\n")
            handle.write(f"magic_byte={os.getenv('WG_OBFUSCATION_MAGIC_BYTE', '0xAA')}\n")
            handle.write(f"WG_OBFS_SERVER_ADDR={ctx.settings.server_ip}:{wg_public_port}\n")
            handle.write("WG_OBFS_SHIM_LISTEN_ADDR=127.0.0.1:51821\n")
            handle.write(f"WG_OBFUSCATION_KEY={wg_obfuscation_key}\n")
            handle.write(
                f"WG_OBFUSCATION_MAGIC_BYTE={os.getenv('WG_OBFUSCATION_MAGIC_BYTE', '0xAA')}\n"
            )
            handle.write(
                "WG_OBFUSCATION_SESSION_IDLE_SECS="
                f"{os.getenv('WG_OBFUSCATION_SESSION_IDLE_SECS', '300')}\n"
            )
        handle.write("\n## Grafana\n")
        handle.write(f"url=http://{ctx.settings.server_ip}:3004\n")
        handle.write(f"username={os.getenv('GRAFANA_ADMIN_USER', 'admin')}\n")
        handle.write(f"password={grafana_password}\n")
        if ctx.settings.deployment_target == "kubernetes":
            handle.write("\n## Integration Console\n")
            handle.write(f"url=http://{ctx.settings.server_ip}:3005\n")
            handle.write("\n## Atheros Search\n")
            handle.write(f"url=http://{ctx.settings.server_ip}:3007\n")
            handle.write("worker=ssl-proxy-vec-worker\n")
            handle.write("\n## Keycloak admin\n")
            handle.write(
                f"url=http://{ctx.settings.server_ip}:8180/admin/middleware/console/\n"
            )
            handle.write("\n## Schema Migrator first login\n")
            handle.write(
                f"url=https://{ctx.settings.schema_migrator_public_hostname or ''}\n"
            )
            handle.write("username=schema-admin\n")
            handle.write(f"temporary_password={schema_admin_password}\n")
            handle.write("password_change_required=true\n")

    for peer_id in peer_names(os.getenv("WG_PEERS", ctx.settings.wg_peers)):
        peer_dir = repo_root() / "config" / peer_id
        direct_cfg = peer_dir / f"{peer_id}.conf"
        obfuscated_cfg = peer_dir / f"{peer_id}-obfuscated.conf"
        selected = (
            direct_cfg
            if ctx.settings.profile_mode in {"iphone", "linux-direct"}
            else obfuscated_cfg
        )
        append_file_section(tmp, f"WireGuard {peer_id} selected config", selected)
        if ctx.settings.profile_mode not in {"iphone", "linux-direct"}:
            append_file_section(tmp, f"WireGuard {peer_id} direct config", direct_cfg)
            append_file_section(tmp, f"WireGuard {peer_id} obfuscated config", obfuscated_cfg)
    os.chmod(tmp, 0o600)
    os.replace(tmp, output)
    os.chmod(output, 0o600)
    step("S09", f"credential_handoff: wrote {output} (0600)")


def diagnostics(ctx: UpReadyContext) -> None:
    step("S08", "diagnostics")
    if ctx.settings.deployment_target == "kubernetes":
        kubernetes_diagnostics(ctx)
        return
    print("--- docker compose ps ---")
    shell.compose("ps", check=False)
    print("--- service health ---")
    for service in ctx.settings.stack_health_service_names:
        cid = (shell.compose("ps", "-q", service, check=False, capture=True).stdout or "").strip()
        status = (
            shell.run(
                ["docker", "inspect", "-f", "{{.State.Status}}", cid], check=False, capture=True
            ).stdout
            or "unknown"
        ).strip()
        health = (
            shell.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                    cid,
                ],
                check=False,
                capture=True,
            ).stdout
            or "unknown"
        ).strip()
        print(f"{service} status={status} health={health}")
    for service in ctx.settings.stack_health_service_names:
        print(f"--- docker compose logs --tail {ctx.settings.log_tail_lines} {service} ---")
        shell.compose("logs", "--tail", str(ctx.settings.log_tail_lines), service, check=False)
    print("--- boringtun show wg0 ---")
    shell.compose(
        "exec",
        "-T",
        ctx.settings.service_name,
        "/app/ssl-proxy",
        "boringtun",
        "show",
        "wg0",
        check=False,
    )
    print("--- listener dump (ss -lunt) ---")
    shell.compose("exec", "-T", ctx.settings.service_name, "sh", "-lc", "ss -lunt", check=False)
    logs = shell.compose(
        "logs", "--tail", str(ctx.settings.log_tail_lines), check=False, capture=True
    )
    text = f"{logs.stdout}\n{logs.stderr}"
    if ctx.last_failed_check:
        text = f"{text}\nLAST_FAILED_CHECK={ctx.last_failed_check}"
    if not ctx.last_failure.matched:
        ctx.classify(text)
    print("--- classified failure ---")
    print(f"class={ctx.last_failure.name}")
    print(f"cause={ctx.last_failure.cause}")
    print(f"fix={ctx.last_failure.fix}")
    print(f"retry={ctx.last_failure.retry}")


def ensure_memory_schema(ctx: UpReadyContext) -> None:
    memory = ctx.settings.memory_file
    if not memory.is_file():
        raise UpReadyError(f"Missing memory file: {memory}")
    text = memory.read_text()
    for heading in [
        "## Environment Matrix",
        "## Known Failure Signatures",
        "## Last Known Good",
        "## Incident Timeline",
        "## Open Risks",
    ]:
        if heading not in text:
            raise UpReadyError(f"Memory file schema invalid: missing {heading.removeprefix('## ')}")


def memo_write(ctx: UpReadyContext, result: str, signature: str, action: str) -> None:
    client_and_arch = f"client={ctx.settings.client_ip} | arch={ctx.host_arch}"
    line = (
        f"- {ctx.run_ts} | result={result} | mode={ctx.settings.profile_mode} | "
        f"server={ctx.settings.server_ip} | {client_and_arch} | "
        f"signature={signature} | action={action}"
    )
    memory = ctx.settings.memory_file
    memory.write_text(insert_incident(memory.read_text(), line))
