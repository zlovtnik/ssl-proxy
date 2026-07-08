from __future__ import annotations

import os
import tempfile
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import typer

try:
    import fcntl
except ImportError:  # pragma: no cover - host scripts target Unix-like systems.
    fcntl = None  # type: ignore[assignment]

from sslproxy_ops.config import Settings

app = typer.Typer(help="Read and append the operational memory ledger.")


class MemoResult(str, Enum):
    passed = "pass"
    failed = "fail"


def _timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def format_timestamp(now: datetime | None = None, tz_name: str | None = None) -> str:
    tz = _timezone(tz_name or os.getenv("TZ", "America/New_York"))
    value = now.astimezone(tz) if now is not None else datetime.now(tz)
    return value.strftime("%Y-%m-%dT%H:%M:%S%z")


def read_memory(memory_file: Path) -> str:
    if not memory_file.is_file():
        raise FileNotFoundError(f"missing memory file: {memory_file}")
    return memory_file.read_text()


def build_entry(
    *,
    event: str,
    context: str,
    result: MemoResult,
    profile_mode: str,
    signature: str,
    action: str,
    timestamp: str | None = None,
) -> str:
    ts = timestamp or format_timestamp()
    event = single_line_field("event", event)
    context = single_line_field("context", context)
    profile_mode = single_line_field("profile_mode", profile_mode)
    signature = single_line_field("signature", signature)
    action = single_line_field("action", action)
    return (
        f"- {ts} | result={result.value} | mode={profile_mode} | signature={signature} "
        f"| action={action} | context={context} | event={event}"
    )


def single_line_field(name: str, value: str) -> str:
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a single line")
    return value


def insert_incident(memory_text: str, entry: str) -> str:
    lines = memory_text.splitlines()
    output: list[str] = []
    inserted = False
    found_section = False

    for line in lines:
        output.append(line)
        if not inserted and line.startswith("## Incident Timeline"):
            found_section = True
            output.append(entry)
            inserted = True

    if not found_section:
        raise ValueError("memory schema invalid: missing Incident Timeline section")

    trailing_newline = "\n" if memory_text.endswith("\n") else ""
    return "\n".join(output) + trailing_newline


def write_incident(memory_file: Path, entry: str) -> None:
    if not memory_file.is_file():
        raise FileNotFoundError(f"missing memory file: {memory_file}")

    lock_file = memory_file.with_name(f"{memory_file.name}.lock")
    with lock_file.open("a+") as lock_handle:
        if fcntl is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            updated = insert_incident(memory_file.read_text(), entry)
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=memory_file.parent,
                prefix=f".{memory_file.name}.",
                delete=False,
            ) as tmp:
                tmp.write(updated)
                tmp_path = Path(tmp.name)
            os.replace(tmp_path, memory_file)
        finally:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _memory_file(option: Path | None) -> Path:
    return option or Settings().memory_file


@app.command("show")
def show(
    memory_file: Annotated[
        Path | None,
        typer.Option("--memory-file", envvar="UP_READY_MEMORY_FILE", help="Memory ledger path."),
    ] = None,
) -> None:
    path = _memory_file(memory_file)
    try:
        typer.echo(read_memory(path), nl=False)
    except FileNotFoundError as exc:
        typer.echo(f"[memo-show][ERROR] {exc}", err=True)
        raise typer.Exit(1) from exc


@app.command("log")
def log(
    event: Annotated[
        str | None,
        typer.Option("--event", envvar="EVENT", help="Incident event summary."),
    ] = None,
    context: Annotated[
        str | None,
        typer.Option("--context", envvar="CONTEXT", help="Incident context."),
    ] = None,
    result: Annotated[
        str | None,
        typer.Option("--result", envvar="RESULT", help="pass or fail."),
    ] = None,
    profile_mode: Annotated[
        str,
        typer.Option("--profile-mode", envvar="PROFILE_MODE", help="Operator profile mode."),
    ] = "unknown",
    signature: Annotated[
        str,
        typer.Option("--signature", envvar="SIGNATURE", help="Failure signature."),
    ] = "none",
    action: Annotated[
        str,
        typer.Option("--action", envvar="ACTION", help="Action taken."),
    ] = "manual-note",
    memory_file: Annotated[
        Path | None,
        typer.Option("--memory-file", envvar="UP_READY_MEMORY_FILE", help="Memory ledger path."),
    ] = None,
) -> None:
    if result not in {item.value for item in MemoResult}:
        typer.echo("[memo-log][ERROR] RESULT must be pass or fail", err=True)
        raise typer.Exit(1)
    if not event or not context:
        typer.echo("[memo-log][ERROR] EVENT and CONTEXT are required.", err=True)
        typer.echo(
            'Example:\n  make memo-log EVENT="iphone tunnel validated" '
            'CONTEXT="server 192.168.1.221 amd64; client 192.168.1.68 iPhone" '
            "RESULT=pass PROFILE_MODE=iphone",
            err=True,
        )
        raise typer.Exit(1)

    path = _memory_file(memory_file)
    try:
        entry = build_entry(
            event=event,
            context=context,
            result=MemoResult(result),
            profile_mode=profile_mode,
            signature=signature,
            action=action,
        )
        write_incident(path, entry)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"[memo-log][ERROR] {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo("[memo-log] inserted incident entry")
