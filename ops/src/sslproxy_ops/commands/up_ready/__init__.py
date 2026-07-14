from __future__ import annotations

import os
import shutil
from typing import Annotated

import typer

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.checks import (
    diagnostics,
    discover_peer_configs,
    ensure_memory_schema,
    health_checks,
    memo_write,
    mode_guardrails,
    network_checks,
    peer_checks,
    qr_render,
    wait_for_container_healthy,
    write_credential_handoff,
)
from sslproxy_ops.commands.up_ready.kubernetes import (
    helm_upgrade,
    kubernetes_diagnostics,
    kubernetes_up,
    sync_kubernetes_secrets,
)
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, desired_obfuscation_value, step, warn
from sslproxy_ops.commands.up_ready.peers import ensure_local_peer_material
from sslproxy_ops.commands.up_ready.secrets import (
    activate_obfuscation_key_env_fallback,
    ensure_admin_api_key_file,
    ensure_secret_bootstrap,
    verify_registry_transport,
)
from sslproxy_ops.config import DeploymentTarget, ProfileMode, Settings

app = typer.Typer(help="Build and deploy the stack, verify services, and print peer QR codes.")


def require_concrete_endpoint_values(settings: Settings) -> None:
    if not settings.server_ip or "<" in settings.server_ip or ">" in settings.server_ip:
        raise UpReadyError("SERVER_IP must be concrete, for example SERVER_IP=192.168.1.221")
    if not settings.client_ip or "<" in settings.client_ip or ">" in settings.client_ip:
        raise UpReadyError("CLIENT_IP must be concrete, for example CLIENT_IP=192.168.1.53")


def apply_profile_runtime_env(ctx: UpReadyContext) -> None:
    ensure_admin_api_key_file()
    match ctx.settings.profile_mode:
        case "iphone":
            # Preserve the established shim endpoint while exposing the
            # boringtun listener on the separate direct-client port.
            os.environ["WG_OBFUSCATION_ENABLED"] = "true"
            os.environ["WG_PORT"] = "443"
            os.environ["WG_INTERNAL_PORT"] = "51820"
            activate_obfuscation_key_env_fallback()
        case "linux-direct":
            os.environ["WG_OBFUSCATION_ENABLED"] = "false"
            os.environ["WG_PORT"] = "443"
            os.environ["WG_INTERNAL_PORT"] = "51820"
        case "linux-shim":
            os.environ["WG_OBFUSCATION_ENABLED"] = "true"
            os.environ["WG_PORT"] = "443"
            os.environ["WG_INTERNAL_PORT"] = "51820"
            activate_obfuscation_key_env_fallback()
        case "mac":
            os.environ["WG_OBFUSCATION_ENABLED"] = "true"
            os.environ["WG_PORT"] = "51820"
            os.environ["WG_INTERNAL_PORT"] = "443"
            activate_obfuscation_key_env_fallback()


def required_stack_healthy(ctx: UpReadyContext) -> bool:
    return all(wait_for_container_healthy(ctx, service) for service in ctx.settings.stack_health_service_names)


def recover_required_compose_stack(ctx: UpReadyContext, phase: str, failure_output: str) -> bool:
    warn(f"{phase} failed; retrying readiness-critical services only: {' '.join(ctx.settings.stack_health_service_names)}")
    step(
        "S03",
        "compose_pull_required: docker compose pull --include-deps "
        + " ".join(ctx.settings.stack_health_service_names),
    )
    pull = shell.compose(
        "pull",
        "--include-deps",
        *ctx.settings.stack_health_service_names,
        check=False,
        capture=True,
    )
    pull_output = f"{pull.stdout or ''}{pull.stderr or ''}"
    if pull.returncode != 0:
        print(pull_output, file=__import__("sys").stderr)
        warn("compose_pull_required failed; attempting compose_up_required with locally available images")

    step("S03", "compose_up_required: docker compose up -d " + " ".join(ctx.settings.stack_health_service_names))
    up = shell.compose("up", "-d", *ctx.settings.stack_health_service_names, check=False, capture=True)
    output = f"{up.stdout or ''}{up.stderr or ''}"
    if up.returncode != 0:
        print(output, file=__import__("sys").stderr)
        ctx.classify(f"{failure_output}\n{pull_output}\n{output}")
        return False

    if required_stack_healthy(ctx):
        warn("Full compose operation failed, but readiness-critical services are healthy; continuing")
        ctx.classify(f"{failure_output}\n{pull_output}")
        return True
    ctx.classify(f"{failure_output}\n{pull_output}")
    return False


def auto_fix(ctx: UpReadyContext, failure_class: str, text: str = "") -> bool:
    if not failure_class or failure_class in ctx.auto_fixed_classes:
        if failure_class:
            warn(f"auto_fix skipped (already attempted): {failure_class}")
        return False

    if ctx.settings.deployment_target == "kubernetes":
        match failure_class:
            case "profile_obfuscation_mismatch":
                apply_profile_runtime_env(ctx)
                helm_upgrade(ctx)
                ctx.auto_fixed_classes.add(failure_class)
                return True
            case "wg_peer_material_missing":
                ensure_local_peer_material(ctx)
                sync_kubernetes_secrets(ctx)
                helm_upgrade(ctx)
                ctx.auto_fixed_classes.add(failure_class)
                return True
            case "admin_loopback_false_negative" | "qr_permission_denied":
                ctx.auto_fixed_classes.add(failure_class)
                return True
        return False

    match failure_class:
        case "docker_registry_dns_timeout":
            step("S09", f"auto_fix[{failure_class}]: recreate with locally available images")
            if shell.compose("up", "-d", "--force-recreate", check=False).returncode == 0:
                ctx.auto_fixed_classes.add(failure_class)
                return True
        case "profile_obfuscation_mismatch":
            desired = desired_obfuscation_value(str(ctx.settings.profile_mode))
            apply_profile_runtime_env(ctx)
            step("S09", f"auto_fix[{failure_class}]: recreate with WG_OBFUSCATION_ENABLED={desired}")
            if shell.compose("up", "-d", "--force-recreate", check=False).returncode == 0:
                ctx.auto_fixed_classes.add(failure_class)
                return True
        case "secret_file_owner_mismatch":
            step("S09", f"auto_fix[{failure_class}]: use direct WG_OBFUSCATION_KEY env fallback and recreate")
            activate_obfuscation_key_env_fallback()
            if (
                shell.compose(
                    "up",
                    "-d",
                    "--force-recreate",
                    ctx.settings.service_name,
                    ctx.settings.frontdoor_service_name,
                    check=False,
                ).returncode
                == 0
            ):
                ctx.auto_fixed_classes.add(failure_class)
                return True
        case "admin_loopback_false_negative" | "qr_permission_denied":
            step("S09", f"auto_fix[{failure_class}]: no-op (handled by fallback path)")
            ctx.auto_fixed_classes.add(failure_class)
            return True
        case "wg_peer_material_missing":
            step("S09", f"auto_fix[{failure_class}]: bootstrap peer material and recreate")
            ensure_local_peer_material(ctx)
            if shell.compose("up", "-d", "--force-recreate", check=False).returncode == 0:
                ctx.auto_fixed_classes.add(failure_class)
                return True
    return False


def compose_up(ctx: UpReadyContext) -> bool:
    step("S03", "compose_pull: docker compose pull")
    pull = shell.compose("pull", check=False, capture=True)
    pull_output = f"{pull.stdout or ''}{pull.stderr or ''}"
    if pull.returncode == 0:
        print(pull_output)
    else:
        print(pull_output, file=__import__("sys").stderr)
        failure = ctx.classify(pull_output)
        if auto_fix(ctx, failure.name, pull_output):
            return True
        if recover_required_compose_stack(ctx, "compose pull", pull_output):
            return True
        return False

    step("S03", "compose_up: docker compose up -d")
    up = shell.compose("up", "-d", check=False, capture=True)
    output = f"{up.stdout or ''}{up.stderr or ''}"
    if up.returncode == 0:
        print(output)
        return True
    print(output, file=__import__("sys").stderr)
    failure = ctx.classify(output)
    if auto_fix(ctx, failure.name, output):
        return True
    if recover_required_compose_stack(ctx, "compose up -d", output):
        return True
    return False


def preflight(ctx: UpReadyContext) -> None:
    step("S01", "preflight")
    commands = ["docker", "curl", "qrencode"]
    if ctx.settings.deployment_target == "kubernetes":
        commands.extend(["helm", "kubectl", "make"])
    for command in commands:
        if shutil.which(command) is None:
            raise UpReadyError(f"Missing required command: {command}")
    if ctx.settings.profile_mode is None:
        raise UpReadyError(
            "PROFILE_MODE is required.\n"
            "Allowed values: iphone | linux-shim | linux-direct | mac\n"
            "Example: make up-ready PROFILE_MODE=mac SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.53"
        )
    require_concrete_endpoint_values(ctx.settings)
    os.environ["WG_PEERS"] = os.getenv("WG_PEERS", ctx.settings.wg_peers)
    ensure_secret_bootstrap(ctx)
    verify_registry_transport(ctx)
    ensure_memory_schema(ctx)


def run_up_ready(ctx: UpReadyContext) -> None:
    preflight(ctx)
    apply_profile_runtime_env(ctx)
    ensure_local_peer_material(ctx)

    deployed = kubernetes_up(ctx) if ctx.settings.deployment_target == "kubernetes" else compose_up(ctx)
    if not deployed:
        diagnostics(ctx)
        memo_write(ctx, "fail", ctx.last_failure.name, ctx.last_failure.fix)
        raise UpReadyError(
            f"{ctx.settings.deployment_target}_up failed: {ctx.last_failure.cause or ctx.last_failure_text}"
        )

    if not mode_guardrails(ctx):
        if auto_fix(ctx, "profile_obfuscation_mismatch", ctx.last_failure_text):
            if not mode_guardrails(ctx):
                diagnostics(ctx)
                memo_write(ctx, "fail", ctx.last_failure.name or "mode_guardrails", ctx.last_failure.fix)
                raise UpReadyError("mode_guardrails failed after bounded auto-fix")
        else:
            diagnostics(ctx)
            memo_write(ctx, "fail", ctx.last_failure.name or "mode_guardrails", ctx.last_failure.fix)
            raise UpReadyError("mode_guardrails failed")

    if not health_checks(ctx) or not network_checks(ctx):
        diagnostics(ctx)
        if auto_fix(ctx, ctx.last_failure.name, ctx.last_failure_text):
            if not health_checks(ctx) or not network_checks(ctx):
                diagnostics(ctx)
                memo_write(ctx, "fail", ctx.last_failure.name, ctx.last_failure.fix)
                raise UpReadyError("checks failed after bounded auto-fix")
        else:
            memo_write(ctx, "fail", ctx.last_failure.name, ctx.last_failure.fix)
            raise UpReadyError("checks failed")

    peer_checks(ctx)
    discover_peer_configs(ctx)
    if not qr_render(ctx):
        diagnostics(ctx)
        memo_write(ctx, "fail", ctx.last_failure.name or "qr_permission_denied", ctx.last_failure.fix)
        raise UpReadyError("qr_render failed")

    write_credential_handoff(ctx)
    memo_write(ctx, "pass", "none", "up-ready completed")
    step("S10", "completed")


@app.callback(invoke_without_command=True)
def up_ready(
    ctx: typer.Context,
    profile_mode: Annotated[ProfileMode | None, typer.Option("--profile-mode", envvar="PROFILE_MODE")] = None,
    server_ip: Annotated[str | None, typer.Option("--server-ip", envvar="SERVER_IP")] = None,
    client_ip: Annotated[str | None, typer.Option("--client-ip", envvar="CLIENT_IP")] = None,
    deployment_target: Annotated[
        DeploymentTarget | None,
        typer.Option("--deployment-target", envvar="UP_READY_DEPLOYMENT_TARGET"),
    ] = None,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    settings = Settings()
    if profile_mode is not None:
        settings.profile_mode = profile_mode
    if server_ip is not None:
        settings.server_ip = server_ip
    if client_ip is not None:
        settings.client_ip = client_ip
    if deployment_target is not None:
        settings.deployment_target = deployment_target
    up_ctx = UpReadyContext(settings=settings)
    try:
        run_up_ready(up_ctx)
    except UpReadyError as exc:
        typer.echo(f"[up-ready][ERROR] {exc}", err=True)
        raise typer.Exit(1) from exc
