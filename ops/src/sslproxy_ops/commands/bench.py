from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table
from rich.console import Console

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root

app = typer.Typer(help="Benchmark operations.")
console = Console()


@dataclass(frozen=True, slots=True)
class IperfCase:
    label: str
    target: str
    args: list[str]


@dataclass(frozen=True, slots=True)
class IperfResult:
    label: str
    target: str
    ok: bool
    summary: str


def snapshot_fragments(output: Path) -> None:
    if shutil.which("netstat"):
        completed = shell.run(["netstat", "-s"], check=False, capture=True)
        lines = [
            line
            for line in (completed.stdout or "").splitlines()
            if "frag" in line.lower() or "reassembl" in line.lower()
        ]
        output.write_text("\n".join(lines) + ("\n" if lines else ""))
    else:
        output.write_text("netstat unavailable\n")


def snapshot_ss(output: Path) -> None:
    if shutil.which("ss"):
        completed = shell.run(["ss", "-s"], check=False, capture=True)
        output.write_text(completed.stdout or "ss unavailable\n")
    else:
        output.write_text("ss unavailable\n")


def parse_iperf_summary(path: Path) -> str:
    if not path.is_file():
        return "missing json"
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return "invalid json"

    end = data.get("end", {})
    if "sum_received" in end:
        bits = end["sum_received"].get("bits_per_second")
    elif "sum" in end:
        bits = end["sum"].get("bits_per_second")
    else:
        bits = None
    if isinstance(bits, int | float):
        return f"{bits / 1_000_000:.2f} Mbit/s"
    error = data.get("error")
    return str(error) if error else "no throughput"


def run_iperf_case(case: IperfCase, out_dir: Path, duration: int, perf_pid: str | None) -> IperfResult:
    if not case.target:
        typer.echo(f"skip {case.label}: target not set")
        return IperfResult(case.label, "", True, "skipped")

    typer.echo(f"run {case.label} -> {case.target}")
    snapshot_ss(out_dir / f"{case.label}.ss.before.txt")
    snapshot_fragments(out_dir / f"{case.label}.fragments.before.txt")

    perf_job: subprocess.Popen[str] | None = None
    if case.label == "obfs-tcp" and perf_pid and shutil.which("perf"):
        perf_file = out_dir / f"{case.label}.perf.txt"
        perf_job = subprocess.Popen(
            [
                "perf",
                "stat",
                "-e",
                "cycles,cache-misses,context-switches",
                "-p",
                perf_pid,
                "-o",
                str(perf_file),
                "--",
                "sleep",
                str(duration),
            ],
            cwd=repo_root(),
            text=True,
        )

    json_path = out_dir / f"{case.label}.iperf.json"
    with json_path.open("w") as handle:
        completed = subprocess.run(
            ["iperf3", "-c", case.target, *case.args, "-J"],
            cwd=repo_root(),
            check=False,
            stdout=handle,
            stderr=subprocess.PIPE,
            text=True,
        )
    if perf_job is not None:
        perf_job.wait()
    snapshot_ss(out_dir / f"{case.label}.ss.after.txt")
    snapshot_fragments(out_dir / f"{case.label}.fragments.after.txt")

    ok = completed.returncode == 0
    typer.echo(("pass" if ok else "fail") + f" {case.label}", err=not ok)
    return IperfResult(case.label, case.target, ok, parse_iperf_summary(json_path))


def normalized_target(value: str | None) -> str:
    return (value or "").strip()


@app.command("wg-path")
def wg_path(
    duration: Annotated[int, typer.Option("--duration", envvar="DURATION")] = 20,
    parallel: Annotated[int, typer.Option("--parallel", envvar="PARALLEL")] = 4,
    udp_bw: Annotated[str, typer.Option("--udp-bw", envvar="UDP_BW")] = "1G",
    out_dir: Annotated[
        Path | None,
        typer.Option("--out-dir", envvar="OUT_DIR"),
    ] = None,
    bypass_target: Annotated[
        str | None,
        typer.Option("--bypass-target", envvar="BYPASS_TARGET"),
    ] = None,
    plain_target: Annotated[
        str | None,
        typer.Option("--plain-target", envvar="PLAIN_TARGET"),
    ] = None,
    obfs_target: Annotated[
        str | None,
        typer.Option("--obfs-target", envvar="OBFS_TARGET"),
    ] = None,
    iperf_server: Annotated[
        str | None,
        typer.Option("--iperf-server", envvar="IPERF_SERVER"),
    ] = None,
    perf_pid: Annotated[str | None, typer.Option("--perf-pid", envvar="PERF_PID")] = None,
) -> None:
    if not shutil.which("iperf3"):
        typer.echo("missing required tool: iperf3", err=True)
        raise typer.Exit(2)

    out_dir = out_dir or repo_root() / "bench-results" / f"wg-path-{datetime.now():%Y%m%d-%H%M%S}"
    out_dir.mkdir(parents=True, exist_ok=True)
    iperf_server = normalized_target(iperf_server)
    bypass_target = normalized_target(bypass_target)
    plain_target = normalized_target(plain_target)
    obfs_target = normalized_target(obfs_target)
    if not any([iperf_server, bypass_target, plain_target, obfs_target]):
        typer.echo("missing benchmark target: set --iperf-server or at least one explicit path target", err=True)
        raise typer.Exit(2)
    bypass_target = bypass_target or iperf_server
    plain_target = plain_target or iperf_server
    obfs_target = obfs_target or iperf_server

    cases = [
        IperfCase("bypass-tcp", bypass_target, ["-t", str(duration), "-P", str(parallel)]),
        IperfCase("bypass-udp", bypass_target, ["-u", "-b", udp_bw, "-t", str(duration)]),
        IperfCase("plain-tcp", plain_target, ["-t", str(duration), "-P", str(parallel)]),
        IperfCase("plain-udp", plain_target, ["-u", "-b", udp_bw, "-t", str(duration)]),
        IperfCase("obfs-tcp", obfs_target, ["-t", str(duration), "-P", str(parallel)]),
        IperfCase("obfs-udp", obfs_target, ["-u", "-b", udp_bw, "-t", str(duration)]),
    ]

    results = [run_iperf_case(case, out_dir, duration, perf_pid) for case in cases]
    table = Table(title="WireGuard path benchmark")
    table.add_column("case")
    table.add_column("target")
    table.add_column("status")
    table.add_column("throughput")
    for result in results:
        table.add_row(result.label, result.target or "-", "pass" if result.ok else "fail", result.summary)
    console.print(table)
    typer.echo(f"results: {out_dir}")
    raise typer.Exit(0 if all(result.ok for result in results) else 1)
