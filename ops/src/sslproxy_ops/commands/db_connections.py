from __future__ import annotations

import json
import re
from typing import Annotated

import httpx
import typer

from sslproxy_ops import shell

app = typer.Typer(help="Database connectivity checks for coordinator services.")


def resolve_container(target: str) -> str:
    inspected = shell.run(["docker", "inspect", target], check=False, capture=True)
    if inspected.returncode == 0:
        return target

    resolved = shell.compose("ps", "-q", target, check=False, capture=True)
    container_id = (resolved.stdout or "").strip()
    return container_id or target


def print_json_endpoint(label: str, url: str) -> bool:
    typer.echo(f"=== {label} ===")
    try:
        response = httpx.get(url, timeout=5.0)
    except httpx.HTTPError as exc:
        typer.echo(f"request_failed error={exc}")
        return False

    try:
        parsed = response.json()
    except json.JSONDecodeError:
        parsed = None

    if 200 <= response.status_code < 300 and parsed is not None:
        typer.echo(json.dumps(parsed, indent=4))
        return True

    if 200 <= response.status_code < 300:
        typer.echo(f"response_parse_failed http_status={response.status_code}")
        body = response.text
        if body:
            typer.echo("\n".join(body.splitlines()[:80]))
        else:
            typer.echo("<empty body>")
        return False

    typer.echo(f"request_failed http_status={response.status_code}")
    body = response.text
    if body:
        typer.echo("\n".join(body.splitlines()[:80]))
    else:
        typer.echo("<empty body>")
    return False


def redact_connection_log(line: str) -> str:
    redacted = re.sub(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)(\s*[=:]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        line,
    )
    redacted = re.sub(r"(?i)\b(host|hostname|server)(\s*[=:]\s*)([^\s,;]+)", r"\1\2[REDACTED]", redacted)
    return redacted


def print_recent_connection_errors(container: str) -> None:
    typer.echo("=== Recent connection errors in logs ===")
    shell.run(["docker", "inspect", container], check=True, capture=True)
    logs = shell.run(["docker", "logs", container], check=False, capture=True)
    text = "\n".join(part for part in [logs.stdout, logs.stderr] if part)
    pattern = re.compile(r"FATAL|CannotGetJdbc|PSQLException|ORA-|HikariPool")
    matches = [line for line in text.splitlines() if pattern.search(line)]
    for line in matches[-20:]:
        typer.echo(redact_connection_log(line))


@app.command("check-connections")
def check_connections(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Container name or compose service."),
    ] = "java-coordinator",
    port: Annotated[
        int,
        typer.Option("--port", "-p", min=1, max=65535, help="Actuator host port."),
    ] = 8081,
) -> None:
    container = resolve_container(target)
    failed = False

    endpoints = [
        ("Actuator Health", "/actuator/health"),
        ("HikariCP Active Connections", "/actuator/metrics/hikaricp.connections.active"),
        ("HikariCP Pending", "/actuator/metrics/hikaricp.connections.pending"),
    ]
    for index, (label, path) in enumerate(endpoints):
        if index:
            typer.echo("")
        failed = not print_json_endpoint(label, f"http://localhost:{port}{path}") or failed

    typer.echo("")
    try:
        print_recent_connection_errors(container)
    except shell.ShellCommandError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(exc.returncode) from exc

    raise typer.Exit(1 if failed else 0)
