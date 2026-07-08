from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Annotated

import typer

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root

app = typer.Typer(help="Host bootstrap and sensor preparation commands.")


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
