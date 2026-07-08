from __future__ import annotations

import os

import typer

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root

app = typer.Typer(help="Schema migrator operations.")


@app.command("smoke")
def smoke() -> None:
    if not os.getenv("DATABASE_URL"):
        typer.echo("DATABASE_URL is required", err=True)
        raise typer.Exit(2)
    cwd = repo_root() / "services" / "schema-migrator"
    for command in [
        "run --sql-dir ../../sql --db-kind postgres list",
        "run --sql-dir ../../sql --db-kind postgres validate",
        "run --sql-dir ../../sql --db-kind postgres apply",
    ]:
        shell.run(["sbt", command], cwd=cwd)

