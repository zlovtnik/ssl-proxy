from __future__ import annotations

import base64
import os
import stat
import zlib
from pathlib import Path

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import is_placeholder_value, peer_names, read_ini_value, trim_key_value


def peer_tunnel_address(peer_id: str) -> str:
    if peer_id == "peer1":
        return "10.13.13.2/32"
    if peer_id == "peer2":
        return "10.13.13.3/32"
    if peer_id.startswith("peer"):
        suffix = peer_id[4:]
        if not suffix.isdigit():
            raise UpReadyError(f"Unsupported peer id: {peer_id}")
        octet = int(suffix) + 1
        if octet < 2 or octet > 254:
            raise UpReadyError(f"Unsupported peer id: {peer_id}")
        return f"10.13.13.{octet}/32"
    octet = (zlib.crc32(peer_id.encode()) % 252) + 2
    return f"10.13.13.{octet}/32"


def read_peer_config_value(peer_id: str, section: str, key: str) -> str | None:
    peer_dir = repo_root() / "config" / peer_id
    for cfg in [peer_dir / f"{peer_id}.conf", peer_dir / f"{peer_id}-obfuscated.conf"]:
        value = read_ini_value(cfg, section, key)
        if value is not None:
            trimmed = trim_key_value(value)
            if not is_placeholder_value(trimmed):
                return trimmed
    return None


def ensure_peer_key_helper(ctx: UpReadyContext) -> None:
    if ctx.peer_key_helper_ready:
        return
    step("S00", "peer_bootstrap: docker compose pull ssl-proxy")
    shell.compose("pull", "ssl-proxy", check=True)
    ctx.peer_key_helper_ready = True


def run_peer_key_helper(*args: str) -> str:
    completed = shell.compose(
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--entrypoint",
        "/app/ssl-proxy",
        "ssl-proxy",
        "boringtun",
        *args,
        capture=True,
    )
    return trim_key_value(completed.stdout or "")


def generate_peer_private_key() -> str:
    return run_peer_key_helper("genkey")


def derive_peer_public_key(private_key: str) -> str:
    return run_peer_key_helper("pubkey", private_key)


def generate_peer_preshared_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def write_secret_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            handle.write("\n")
    finally:
        try:
            os.chmod(path, mode)
        except FileNotFoundError:
            pass


def render_direct_peer_config(peer_id: str, private_key: str, preshared_key: str, server_ip: str) -> None:
    output = repo_root() / "config" / peer_id / f"{peer_id}.conf"
    address = peer_tunnel_address(peer_id)
    endpoint_port = os.getenv("WG_PORT", "443")
    mtu = os.getenv("WG_MTU", "1420")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        f"""# Raw direct WireGuard reference profile only.
# This profile is not usable against an obfuscation-only public server port.
# When WG_OBFUSCATION_ENABLED=true on the server, use {peer_id}-obfuscated.conf plus a local UDP shim instead.
[Interface]
Address = {address}
PrivateKey = {private_key}
ListenPort = 51820
MTU = {mtu}
DNS = 10.13.13.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = {preshared_key}
# Endpoint must be the Docker host's LAN/public IP, not a container bridge IP.
Endpoint = {server_ip}:{endpoint_port}
AllowedIPs = 0.0.0.0/0, ::/0
"""
    )
    os.chmod(output, 0o600)
    step("S00", f"peer_bootstrap: wrote {output}")


def render_obfuscated_peer_config(peer_id: str, private_key: str, preshared_key: str) -> None:
    peer_dir = repo_root() / "config" / peer_id
    example = peer_dir / f"{peer_id}-obfuscated.conf.example"
    output = peer_dir / f"{peer_id}-obfuscated.conf"
    if example.is_file():
        text = example.read_text()
        text = text.replace(f"<{peer_id}-private-key>", private_key)
        text = text.replace(f"<{peer_id}-preshared-key>", preshared_key)
        output.write_text(text)
    else:
        address = peer_tunnel_address(peer_id)
        mtu = os.getenv("WG_MTU", "1419")
        output.write_text(
            f"""# Supported client path when UDP obfuscation is enabled on the server.
[Interface]
Address = {address}
PrivateKey = {private_key}
ListenPort = 443
MTU = {mtu}
DNS = 10.13.13.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = {preshared_key}
Endpoint = 127.0.0.1:51821
AllowedIPs = 0.0.0.0/0, ::/0
"""
        )
    os.chmod(output, 0o600)
    step("S00", f"peer_bootstrap: wrote {output}")


def peer_material_complete(peer_id: str) -> bool:
    peer_dir = repo_root() / "config" / peer_id
    return all(
        path.is_file() and path.stat().st_size > 0
        for path in [
            peer_dir / f"publickey-{peer_id}",
            peer_dir / f"presharedkey-{peer_id}",
            peer_dir / f"{peer_id}.conf",
            peer_dir / f"{peer_id}-obfuscated.conf",
        ]
    )


def ensure_one_peer_material(ctx: UpReadyContext, peer_id: str) -> None:
    peer_dir = repo_root() / "config" / peer_id
    peer_dir.mkdir(parents=True, exist_ok=True)
    private_key_file = peer_dir / f"privatekey-{peer_id}"
    public_key_file = peer_dir / f"publickey-{peer_id}"
    preshared_key_file = peer_dir / f"presharedkey-{peer_id}"

    private_key = trim_key_value(private_key_file.read_text()) if private_key_file.is_file() else ""
    if is_placeholder_value(private_key):
        private_key = read_peer_config_value(peer_id, "Interface", "PrivateKey") or ""
    if is_placeholder_value(private_key):
        private_key = generate_peer_private_key()
        step("S00", f"peer_bootstrap: generated private key for {peer_id}")
    if not private_key:
        raise UpReadyError(f"Unable to resolve private key for {peer_id}")
    if not private_key_file.is_file() or private_key_file.stat().st_size == 0:
        write_secret_text(private_key_file, private_key, 0o600)

    public_key = trim_key_value(public_key_file.read_text()) if public_key_file.is_file() else ""
    if is_placeholder_value(public_key):
        public_key = derive_peer_public_key(private_key)
        write_secret_text(public_key_file, public_key, 0o644)
        step("S00", f"peer_bootstrap: wrote public key for {peer_id}")

    preshared_key = trim_key_value(preshared_key_file.read_text()) if preshared_key_file.is_file() else ""
    if is_placeholder_value(preshared_key):
        preshared_key = read_peer_config_value(peer_id, "Peer", "PresharedKey") or ""
    if is_placeholder_value(preshared_key):
        preshared_key = generate_peer_preshared_key()
        step("S00", f"peer_bootstrap: generated preshared key for {peer_id}")
    if not preshared_key:
        raise UpReadyError(f"Unable to resolve preshared key for {peer_id}")
    if not preshared_key_file.is_file() or preshared_key_file.stat().st_size == 0:
        write_secret_text(preshared_key_file, preshared_key, 0o600)

    if not (peer_dir / f"{peer_id}.conf").is_file():
        render_direct_peer_config(peer_id, private_key, preshared_key, ctx.settings.server_ip)
    if not (peer_dir / f"{peer_id}-obfuscated.conf").is_file():
        render_obfuscated_peer_config(peer_id, private_key, preshared_key)


def ensure_local_peer_material(ctx: UpReadyContext) -> None:
    peers = peer_names(os.getenv("WG_PEERS", ctx.settings.wg_peers))
    if all(peer_material_complete(peer_id) for peer_id in peers):
        return
    ensure_peer_key_helper(ctx)
    for peer_id in peers:
        ensure_one_peer_material(ctx, peer_id)

