from __future__ import annotations

import typer

from sslproxy_ops.commands import (
    bench,
    db_connections,
    diagnose,
    host,
    memo,
    pipeline,
    schema_migrator,
    secrets,
    smoke,
    up_ready,
)
from sslproxy_ops.stack import core as stack

app = typer.Typer(no_args_is_help=True, help="ssl-proxy host operations CLI.")
app.add_typer(memo.app, name="memo")
app.add_typer(db_connections.app, name="db")
app.add_typer(up_ready.app, name="up-ready")
app.add_typer(diagnose.app, name="diagnose")
app.add_typer(pipeline.app, name="pipeline")
app.add_typer(bench.app, name="bench")
app.add_typer(smoke.app, name="smoke")
app.add_typer(schema_migrator.app, name="schema-migrator")
app.add_typer(host.app, name="host")


@app.command(
    "stack",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def stack_command(ctx: typer.Context) -> None:
    """Plan, validate, deploy, inspect, and cut over split Helm releases."""

    raise typer.Exit(stack.main(list(ctx.args)))


@app.command("secrets", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def secrets_command(ctx: typer.Context) -> None:
    """Generated secret management wrapper."""

    try:
        code = secrets.run(list(ctx.args))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(64) from exc
    raise typer.Exit(code)


def main() -> None:
    app()
