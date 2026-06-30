from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Annotated, Literal

import httpx
import typer

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root

app = typer.Typer(help="End-to-end smoke tests.")


class SmokeFailure(RuntimeError):
    pass


def cleanup() -> None:
    typer.echo("[smoke] cleaning up")
    shell.compose("down", "-v", "--remove-orphans", check=False, capture=True)


def current_vcs_ref() -> str:
    return (shell.run(["git", "rev-parse", "--short", "HEAD"], capture=True).stdout or "").strip()


def current_build_date() -> str:
    return (shell.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture=True).stdout or "").strip()


def compose_env(vcs_ref: str, build_date: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    return {**os.environ, "VCS_REF": vcs_ref, "BUILD_DATE": build_date, **(extra or {})}


def wait_for_health(timeout: int = 60) -> None:
    typer.echo(f"[smoke] waiting for admin liveness and BoringTun health ({timeout}s)")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        host_ok = False
        try:
            response = httpx.get("http://127.0.0.1:3002/health", timeout=2.0)
            host_ok = 200 <= response.status_code < 300
        except httpx.HTTPError:
            host_ok = False
        container_ok = (
            shell.compose(
                "exec",
                "-T",
                "ssl-proxy",
                "curl",
                "-f",
                "-s",
                "http://127.0.0.1:3002/health",
                check=False,
                capture=True,
            ).returncode
            == 0
        )
        wg_ok = (
            shell.compose(
                "exec",
                "-T",
                "ssl-proxy",
                "/app/ssl-proxy",
                "boringtun",
                "show",
                "wg0",
                check=False,
                capture=True,
            ).returncode
            == 0
        )
        if (host_ok or container_ok) and wg_ok:
            typer.echo("[smoke] admin liveness and BoringTun checks passed")
            return
        time.sleep(1)
    shell.compose("logs", check=False)
    raise SmokeFailure("timeout waiting for service to become healthy")


def expected_ready_status() -> str:
    alias = os.getenv("ORACLE_CONN", "mainerc_high").lower()
    wallet = repo_root() / "wallet"
    tns = wallet / "tnsnames.ora"
    sqlnet = wallet / "sqlnet.ora"
    cwallet = wallet / "cwallet.sso"
    found_alias = False
    if tns.is_file():
        for raw_line in tns.read_text(errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            lhs = line.split("=", 1)[0].strip().lower()
            if lhs == alias:
                found_alias = True
                break
    return "200" if found_alias and sqlnet.is_file() and cwallet.is_file() else "503"


def assert_ready_status(expected: str) -> None:
    body = ""
    code = "000"
    try:
        response = httpx.get("http://127.0.0.1:3002/ready", timeout=2.0)
        code = str(response.status_code)
        body = response.text
    except httpx.HTTPError:
        pass
    if code in {"000", "52"}:
        completed = shell.compose(
            "exec",
            "-T",
            "ssl-proxy",
            "curl",
            "-s",
            "-o",
            "/tmp/smoke-ready-body.txt",
            "-w",
            "%{http_code}",
            "http://127.0.0.1:3002/ready",
            check=False,
            capture=True,
        )
        code = (completed.stdout or "").strip()
        body = (
            shell.compose(
                "exec",
                "-T",
                "ssl-proxy",
                "sh",
                "-lc",
                "cat /tmp/smoke-ready-body.txt",
                check=False,
                capture=True,
            ).stdout
            or ""
        )
    if code != expected:
        typer.echo(f"[smoke][ERROR] unexpected /ready status: expected {expected} got {code}")
        typer.echo("Body:")
        typer.echo(body)
        shell.compose("logs", check=False)
        raise SmokeFailure("unexpected /ready status")
    typer.echo(f"[smoke] /ready returned expected status {code}")


def assert_wg_interface() -> None:
    typer.echo("[smoke] checking BoringTun interface status")
    completed = shell.compose(
        "exec",
        "-T",
        "ssl-proxy",
        "/app/ssl-proxy",
        "boringtun",
        "show",
        "wg0",
        capture=True,
    )
    typer.echo(completed.stdout or "")
    if "interface: wg0" not in (completed.stdout or ""):
        raise SmokeFailure("BoringTun interface output was unexpected")


def assert_unique_server_address() -> None:
    count_text = (
        shell.compose(
            "exec",
            "-T",
            "ssl-proxy",
            "sh",
            "-lc",
            "grep -c '^Address = 10.13.13.1/24$' /run/wireguard/wg0.conf || true",
            capture=True,
        ).stdout
        or "0"
    ).strip()
    count = int(count_text or "0")
    if count != 1:
        typer.echo(f"[smoke][ERROR] expected one rendered server address, found {count}")
        shell.compose("exec", "-T", "ssl-proxy", "sh", "-lc", "nl -ba /run/wireguard/wg0.conf", check=False)
        raise SmokeFailure("duplicate server address")
    logs = shell.compose("logs", "ssl-proxy", check=False, capture=True).stdout or ""
    if "Address already assigned" in logs:
        typer.echo(logs)
        raise SmokeFailure("duplicate address regression detected")
    typer.echo("[smoke] rendered BoringTun config contains one unique server address")


def assert_userspace_runtime_only() -> None:
    for tool in ["wg", "wg-quick", "modprobe"]:
        if (
            shell.compose(
                "exec",
                "-T",
                "ssl-proxy",
                "sh",
                "-lc",
                f"command -v {tool} >/dev/null 2>&1",
                check=False,
                capture=True,
            ).returncode
            == 0
        ):
            raise SmokeFailure(f"unexpected legacy tooling still present: {tool}")
    if (
        shell.compose(
            "exec",
            "-T",
            "ssl-proxy",
            "sh",
            "-lc",
            "command -v boringtun-cli >/dev/null 2>&1",
            check=False,
            capture=True,
        ).returncode
        != 0
    ):
        raise SmokeFailure("expected boringtun-cli to be present")
    typer.echo("[smoke] container contains BoringTun userspace tooling only")


def assert_startup_fingerprint(raw_address: str, normalized_address: str, vcs_ref: str) -> None:
    logs = shell.compose("logs", "ssl-proxy", check=False, capture=True).stdout or ""
    if f"[startup-fingerprint] revision={vcs_ref} build_date=" not in logs or "entrypoint_sha256=" not in logs:
        typer.echo(logs)
        raise SmokeFailure("startup fingerprint revision or checksum missing")
    expected = (
        "[startup-fingerprint] "
        f"raw_wg_server_address={raw_address} normalized_wg_server_address={normalized_address} "
        "wg_config_path=/run/wireguard/wg0.conf"
    )
    if expected not in logs:
        typer.echo(logs)
        raise SmokeFailure("startup fingerprint address normalization details missing")
    typer.echo("[smoke] startup fingerprint is present in container logs")


def inject_duplicate_template_address() -> Path:
    template = repo_root() / "config" / "templates" / "server.conf"
    fd, backup_name = tempfile.mkstemp(prefix="sslproxy-server-conf.")
    os.close(fd)
    backup = Path(backup_name)
    shutil.copy(template, backup)
    lines = template.read_text().splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == "Address = __WG_SERVER_ADDRESS__":
            lines.insert(idx + 1, line)
            break
    else:
        raise SmokeFailure("missing Address placeholder in config/templates/server.conf")
    template.write_text("\n".join(lines) + "\n")
    return backup


def restore_template(backup: Path | None) -> None:
    if backup is not None and backup.is_file():
        shutil.move(str(backup), repo_root() / "config" / "templates" / "server.conf")


def run_default_scenario(vcs_ref: str, build_date: str) -> None:
    typer.echo("[smoke] bringing up default stack")
    cleanup()
    shell.compose("up", "-d", "--build", env=compose_env(vcs_ref, build_date))
    wait_for_health()
    assert_ready_status(expected_ready_status())
    assert_startup_fingerprint("10.13.13.1/24", "10.13.13.1/24", vcs_ref)
    assert_wg_interface()
    assert_unique_server_address()
    assert_userspace_runtime_only()


def run_duplicate_address_scenario(vcs_ref: str, build_date: str) -> None:
    typer.echo("[smoke] re-running with duplicated WG_SERVER_ADDRESS input")
    cleanup()
    shell.compose(
        "up",
        "-d",
        "--build",
        env=compose_env(vcs_ref, build_date, {"WG_SERVER_ADDRESS": "10.13.13.1/24,10.13.13.1/24"}),
    )
    wait_for_health()
    assert_ready_status(expected_ready_status())
    assert_startup_fingerprint("10.13.13.1/24,10.13.13.1/24", "10.13.13.1/24", vcs_ref)
    assert_wg_interface()
    assert_unique_server_address()


def run_duplicate_template_scenario(vcs_ref: str, build_date: str) -> None:
    typer.echo("[smoke] re-running with drifted template containing duplicate Address lines")
    cleanup()
    backup = inject_duplicate_template_address()
    try:
        shell.compose("up", "-d", "--build", env=compose_env(vcs_ref, build_date))
        wait_for_health()
        assert_ready_status(expected_ready_status())
        assert_startup_fingerprint("10.13.13.1/24", "10.13.13.1/24", vcs_ref)
        assert_wg_interface()
        assert_unique_server_address()
    finally:
        restore_template(backup)


@app.callback(invoke_without_command=True)
def smoke(
    ctx: typer.Context,
    scenario: Annotated[
        Literal["all", "default", "duplicate-address", "duplicate-template"],
        typer.Option("--scenario"),
    ] = "all",
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    typer.echo("[smoke] starting SSL Proxy smoke test")
    vcs_ref = current_vcs_ref()
    build_date = current_build_date()
    try:
        if scenario in {"all", "default"}:
            run_default_scenario(vcs_ref, build_date)
        if scenario in {"all", "duplicate-address"}:
            run_duplicate_address_scenario(vcs_ref, build_date)
        if scenario in {"all", "duplicate-template"}:
            run_duplicate_template_scenario(vcs_ref, build_date)
    except SmokeFailure as exc:
        typer.echo(f"[smoke][ERROR] {exc}", err=True)
        raise typer.Exit(1) from exc
    finally:
        cleanup()
    typer.echo("")
    typer.echo("[smoke] skipping explicit proxy request test because default compose uses transparent-only mode.")
    typer.echo("[smoke] all smoke tests passed successfully")

