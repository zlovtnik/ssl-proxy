from __future__ import annotations

from typing import Annotated

import typer

from sslproxy_ops import shell
from sslproxy_ops.config import Settings

app = typer.Typer(help="Sync pipeline operations.")


def section(title: str) -> None:
    typer.echo("")
    typer.echo(f"== {title} ==")


def run_allow_fail(cmd: list[str]) -> None:
    shell.run(cmd, check=False, capture=False)


@app.command("status")
def status(
    scan_topic: Annotated[
        str | None,
        typer.Option("--scan-topic", envvar="SYNC_SCAN_TOPIC"),
    ] = None,
    scan_consumer: Annotated[
        str | None,
        typer.Option("--scan-consumer", envvar="SYNC_SCAN_CONSUMER"),
    ] = None,
) -> None:
    settings = Settings()
    scan_topic = scan_topic or settings.sync_scan_topic
    scan_consumer = scan_consumer or settings.sync_scan_consumer
    brokers = settings.sync_redpanda_bootstrap_servers
    compose_project = settings.compose_project_name
    redpanda_image = settings.redpanda_image

    typer.echo("== compose services ==")
    run_allow_fail(
        [
            "docker",
            "compose",
            "ps",
            "redpanda",
            "redpanda-init",
            "java-coordinator",
            "atheros-sensor",
        ]
    )

    rpk_base = [
        "docker",
        "run",
        "--rm",
        "--network",
        f"{compose_project}_default",
        "--entrypoint",
        "rpk",
        redpanda_image,
    ]
    section("redpanda cluster")
    run_allow_fail([*rpk_base, "cluster", "info", "--brokers", brokers])
    section("redpanda topics")
    run_allow_fail([*rpk_base, "topic", "list", "--brokers", brokers])
    section("redpanda scan topic")
    run_allow_fail([*rpk_base, "topic", "describe", scan_topic, "--brokers", brokers])
    section("redpanda scan consumer group")
    run_allow_fail([*rpk_base, "group", "describe", scan_consumer, "--brokers", brokers])
