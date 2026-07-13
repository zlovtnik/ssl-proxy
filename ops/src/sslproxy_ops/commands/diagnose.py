from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from typing import Annotated, Literal

import httpx
import typer

from sslproxy_ops import shell
from sslproxy_ops.config import ProfileMode, Settings
from sslproxy_ops.health import HealthCheck, HealthResult, run_checks
from sslproxy_ops.health.signatures import classify_text

app = typer.Typer(help="Non-mutating diagnosis and failure classification.")


@dataclass(frozen=True, slots=True)
class DiagnoseReport:
    profile_mode: str
    server_ip: str
    client_ip: str
    services: list[HealthResult]
    desired_obfuscation: str
    actual_obfuscation: str
    host_admin_ok: bool
    container_admin_ok: bool
    classification: dict[str, str | bool]


def desired_obfuscation_value(profile_mode: str) -> str:
    return "true" if profile_mode in {"iphone", "linux-shim", "mac"} else "false"


def runtime_obfuscation_value(service_name: str) -> str:
    logs = shell.compose("logs", "--tail", "200", service_name, check=False, capture=True)
    matches = re.findall(r"wg_obfuscation_enabled=(true|false)", logs.stdout or "")
    return matches[-1] if matches else "unknown"


def inspect_service(service: str) -> HealthResult:
    cid = (shell.compose("ps", "-q", service, check=False, capture=True).stdout or "").strip()
    if not cid:
        return HealthResult(service, False, "missing container")
    status = (
        shell.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", cid],
            check=False,
            capture=True,
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
    ok = status == "running" and health in {"healthy", "none"}
    detail = f"status={status} health={health}"
    if health == "unhealthy":
        detail = f"{detail}\n{service} unhealthy"
    return HealthResult(service, ok, detail)


async def check_host_admin() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get("http://127.0.0.1:3002/health")
            return 200 <= response.status_code < 300
    except httpx.HTTPError:
        return False


def check_container_admin(service_name: str) -> bool:
    return (
        shell.compose(
            "exec",
            "-T",
            service_name,
            "curl",
            "-fsS",
            "--max-time",
            "2",
            "http://127.0.0.1:3002/health",
            check=False,
            capture=True,
        ).returncode
        == 0
    )


async def build_report(settings: Settings, profile_mode: str) -> DiagnoseReport:
    service_checks = [
        HealthCheck(service, lambda service=service: inspect_service(service))
        for service in settings.stack_health_service_names
    ]
    admin_checks = [
        HealthCheck("host_admin", check_host_admin),
        HealthCheck("container_admin", lambda: check_container_admin(settings.service_name)),
    ]
    results = await run_checks([*service_checks, *admin_checks])
    services = results[: len(service_checks)]
    host_admin_ok = results[len(service_checks)].ok
    container_admin_ok = results[len(service_checks) + 1].ok
    actual = runtime_obfuscation_value(settings.service_name)
    desired = desired_obfuscation_value(profile_mode)

    logs = shell.compose("logs", "--tail", str(settings.log_tail_lines), check=False, capture=True)
    health_text = "\n".join(result.detail for result in services)
    classification = classify_text(f"{health_text}\n{logs.stdout}\n{logs.stderr}")

    return DiagnoseReport(
        profile_mode=profile_mode,
        server_ip=settings.server_ip,
        client_ip=settings.client_ip,
        services=services,
        desired_obfuscation=desired,
        actual_obfuscation=actual,
        host_admin_ok=host_admin_ok,
        container_admin_ok=container_admin_ok,
        classification={
            "class": classification.name,
            "cause": classification.cause,
            "fix": classification.fix,
            "retry": classification.retry,
            "matched": classification.matched,
        },
    )


def print_report(report: DiagnoseReport, settings: Settings) -> None:
    typer.echo(
        f"[diagnose] mode={report.profile_mode} server={report.server_ip} client={report.client_ip}"
    )
    typer.echo("--- compose ps ---")
    shell.compose("ps", check=False)
    typer.echo("--- service health ---")
    for result in report.services:
        typer.echo(f"{result.name} {result.detail}")
    typer.echo("--- runtime obfuscation ---")
    typer.echo(f"desired={report.desired_obfuscation}")
    typer.echo(f"actual={report.actual_obfuscation}")
    typer.echo("--- admin health ---")
    typer.echo(f"host={'ok' if report.host_admin_ok else 'fail'}")
    typer.echo(f"container={'ok' if report.container_admin_ok else 'fail'}")
    typer.echo("--- boringtun show ---")
    shell.compose(
        "exec",
        "-T",
        settings.service_name,
        "/app/ssl-proxy",
        "boringtun",
        "show",
        "wg0",
        check=False,
    )
    typer.echo("--- listeners ---")
    shell.compose(
        "exec",
        "-T",
        settings.service_name,
        "sh",
        "-lc",
        "ss -lunt; ss -lun",
        check=False,
    )
    for service in settings.stack_health_service_names:
        typer.echo(f"--- logs tail ({settings.log_tail_lines}) {service} ---")
        shell.compose("logs", "--tail", str(settings.log_tail_lines), service, check=False)
    typer.echo("--- classification ---")
    typer.echo(f"class={report.classification['class']}")
    typer.echo(f"cause={report.classification['cause']}")
    typer.echo(f"fix={report.classification['fix']}")
    typer.echo(f"retry={report.classification['retry']}")


@app.callback(invoke_without_command=True)
def diagnose(
    ctx: typer.Context,
    profile_mode: Annotated[
        ProfileMode | None,
        typer.Option("--profile-mode", envvar="PROFILE_MODE"),
    ] = None,
    server_ip: Annotated[str | None, typer.Option("--server-ip", envvar="SERVER_IP")] = None,
    client_ip: Annotated[str | None, typer.Option("--client-ip", envvar="CLIENT_IP")] = None,
    output: Annotated[Literal["text", "json"], typer.Option("--output")] = "text",
    json_flag: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    settings = Settings()
    mode = profile_mode or settings.profile_mode
    if mode is None:
        typer.echo(
            "[diagnose][ERROR] PROFILE_MODE is required.\n"
            "Allowed values: iphone | linux-shim | linux-direct | mac\n"
            "Example: make diagnose PROFILE_MODE=mac SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.53",
            err=True,
        )
        raise typer.Exit(1)

    if server_ip is not None:
        settings.server_ip = server_ip
    if client_ip is not None:
        settings.client_ip = client_ip

    report = asyncio.run(build_report(settings, mode))
    if json_flag or output == "json":
        typer.echo(json.dumps(asdict(report), indent=2))
    else:
        print_report(report, settings)
