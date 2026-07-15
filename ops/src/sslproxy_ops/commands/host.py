from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Annotated

import typer

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root

app = typer.Typer(help="Host bootstrap and sensor preparation commands.")


def normalize_registry_authority(value: str) -> str:
    registry = re.sub(r"^https?://", "", value.strip()).rstrip("/")
    if not registry or "/" in registry or any(char.isspace() for char in registry):
        raise ValueError("registry must be a host[:port] without a URL path")
    return registry


def containerd_registry_hosts_toml(registry: str, *, plain_http: bool) -> str:
    scheme = "http" if plain_http else "https"
    endpoint = f"{scheme}://{registry}"
    return (
        f'server = "{endpoint}"\n\n'
        f'[host."{endpoint}"]\n'
        '  capabilities = ["pull", "resolve"]\n'
    )


def write_host_config(path: Path, content: str) -> bool:
    if path.is_file() and path.read_text() == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o644)
    return True


@app.command("prep-ath")
def prep_ath(
    interface: Annotated[str | None, typer.Argument(help="Wireless interface.")] = None,
    reg_domain: Annotated[str, typer.Option("--reg-domain", envvar="ATH_SENSOR_REG_DOMAIN")] = "US",
    channel: Annotated[str, typer.Option("--channel", envvar="ATH_SENSOR_CHANNEL")] = "6",
) -> None:
    iface = interface or os.getenv("ATH_SENSOR_DEVICE", "wlan0")
    shell.run(["iw", "reg", "set", reg_domain])
    shell.run(["ip", "link", "set", iface, "down"])
    shell.run(["iw", iface, "set", "monitor", "control"])
    shell.run(["ip", "link", "set", iface, "up"])
    shell.run(["iw", "dev", iface, "set", "channel", channel])


@app.command("setup-ubuntu")
def setup_ubuntu() -> None:
    if os.geteuid() != 0:
        typer.echo("Error: this command must be run as root, for example sudo ops host setup-ubuntu", err=True)
        raise typer.Exit(1)
    if shutil.which("docker") is None:
        if shutil.which("curl") is None:
            shell.run(["apt-get", "update"])
            shell.run(["apt-get", "install", "-y", "curl"])
        installer = shell.run(["curl", "-fsSL", "https://get.docker.com"], capture=True)
        shell.run(["sh"], input_text=installer.stdout or "")
        sudo_user = os.getenv("SUDO_USER")
        if sudo_user:
            shell.run(["usermod", "-aG", "docker", sudo_user])
            typer.echo(
                f"Note: '{sudo_user}' added to docker group. Run 'newgrp docker' or log out and back in to apply."
            )
    shell.compose("up", "-d", "--build", cwd=repo_root())


@app.command("configure-containerd-registry")
def configure_containerd_registry(
    registry: Annotated[
        str | None,
        typer.Option("--registry", envvar="REGISTRY", help="Canonical registry host:port."),
    ] = None,
    plain_http: Annotated[
        bool,
        typer.Option("--plain-http/--tls", help="Use HTTP only on a trusted private network."),
    ] = True,
    probe_image: Annotated[
        str,
        typer.Option("--probe-image", help="Repository:tag to pull with crictl after restart."),
    ] = "redis:7-alpine",
) -> None:
    """Configure containerd 2.x CRI pulls from the canonical local registry."""
    if os.geteuid() != 0:
        typer.echo(
            "Error: run through `make configure-containerd-registry "
            "REGISTRY=192.168.1.221:5000`, which requests sudo",
            err=True,
        )
        raise typer.Exit(1)

    candidate = registry or (
        f"{os.environ['SERVER_IP']}:5000" if os.getenv("SERVER_IP") else ""
    )
    try:
        authority = normalize_registry_authority(candidate)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc

    config_path = Path("/etc/containerd/config.toml")
    if not config_path.is_file():
        typer.echo(f"Error: missing {config_path}", err=True)
        raise typer.Exit(1)
    config_text = config_path.read_text()
    if "/etc/containerd/conf.d/*.toml" not in config_text:
        typer.echo(
            "Error: /etc/containerd/config.toml does not import "
            "/etc/containerd/conf.d/*.toml; add that import before using this command",
            err=True,
        )
        raise typer.Exit(1)

    cri_drop_in = Path("/etc/containerd/conf.d/ssl-proxy-registry.toml")
    hosts_path = Path("/etc/containerd/certs.d") / authority / "hosts.toml"
    changed = write_host_config(
        cri_drop_in,
        "version = 3\n\n"
        "[plugins.'io.containerd.cri.v1.images'.registry]\n"
        "  config_path = '/etc/containerd/certs.d'\n",
    )
    changed = (
        write_host_config(
            hosts_path,
            containerd_registry_hosts_toml(authority, plain_http=plain_http),
        )
        or changed
    )

    if changed:
        shell.run(["systemctl", "restart", "containerd"])
    shell.run(["systemctl", "is-active", "--quiet", "containerd"])
    if probe_image:
        shell.run(["crictl", "pull", f"{authority}/{probe_image}"])
    typer.echo(
        f"containerd registry ready: {authority} "
        f"({'plain HTTP' if plain_http else 'TLS'})"
    )


@app.command("shellcheck-tier-b")
def shellcheck_tier_b() -> None:
    scripts = {
        "bash": [
            repo_root() / "docker" / "entrypoint.sh",
            repo_root() / "docker" / "minio" / "init.sh",
        ],
        "sh": [
            repo_root() / "docker" / "redpanda" / "bootstrap.sh",
            repo_root() / "services" / "zig-coordinator" / "setup-wireless-redpanda.sh",
        ],
    }
    failed = False
    if shutil.which("shellcheck") is not None:
        for shell_name, paths in scripts.items():
            completed = shell.run(["shellcheck", "-s", shell_name, *paths], check=False)
            failed = failed or completed.returncode != 0
    else:
        root = repo_root()
        for shell_name, paths in scripts.items():
            mounted = [f"/mnt/{path.relative_to(root)}" for path in paths]
            completed = shell.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{root}:/mnt",
                    "koalaman/shellcheck:stable",
                    "-s",
                    shell_name,
                    *mounted,
                ],
                check=False,
            )
            failed = failed or completed.returncode != 0
    raise typer.Exit(1 if failed else 0)
