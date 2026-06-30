from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import httpx

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError, step, warn
from sslproxy_ops.paths import repo_root
from sslproxy_ops.util.ini import contains_unresolved_placeholder, is_placeholder_value, read_dotenv_value, trim_key_value


REQUIRED_DOTENV_KEYS = [
    "REGISTRY",
    "IMAGE_TAG",
    "POSTGRES_PASSWORD",
    "MINIO_ACCESS_KEY_ID",
    "MINIO_SECRET_ACCESS_KEY",
    "GRAFANA_ADMIN_PASSWORD",
    "ATHSEARCH_API_TOKEN_SHA256",
    "ADMIN_API_KEY_FILE",
    "WG_OBFUSCATION_KEY_FILE",
    "WAHA_API_KEY",
    "WAHA_DASHBOARD_PASSWORD",
    "WHATSAPP_SWAGGER_PASSWORD",
]


def ensure_secret_file(path: Path, label: str) -> None:
    if path.is_file() and path.stat().st_size > 0:
        return
    raise UpReadyError(f"Missing {label} secret at {path}; run scripts/gen-secrets generate")


def ensure_admin_api_key_file() -> None:
    if os.getenv("ADMIN_API_KEY"):
        return
    ensure_secret_file(repo_root() / "secrets" / "admin_api_key", "admin API key")


def activate_obfuscation_key_env_fallback() -> None:
    path = repo_root() / "secrets" / "wg_obfuscation_key"
    ensure_secret_file(path, "WireGuard obfuscation key")
    value = trim_key_value(path.read_text())
    if is_placeholder_value(value):
        raise UpReadyError("WireGuard obfuscation key is empty or unresolved")
    os.environ["WG_OBFUSCATION_KEY"] = value


def default_registry_value(server_ip: str) -> str:
    return f"{server_ip}:5000"


def registry_host_value(registry: str) -> str:
    registry = re.sub(r"^https?://", "", registry)
    return registry.split("/", 1)[0]


def registry_plain_http_enabled(registry_host: str, plain_http: str) -> bool:
    if plain_http == "auto":
        return bool(
            registry_host.startswith(("localhost:", "127.", "10.", "192.168."))
            or re.match(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", registry_host)
        )
    if plain_http in {"1", "true", "yes"}:
        return True
    if plain_http in {"0", "false", "no"}:
        return False
    raise UpReadyError("REGISTRY_PLAIN_HTTP must be auto, 1, or 0")


def docker_daemon_lists_insecure_registry(registry_host: str) -> bool:
    if registry_host.startswith(("localhost:", "127.")):
        return True
    info = shell.run(["docker", "info"], check=False, capture=True)
    text = info.stdout or ""
    if registry_host in text:
        return True
    host_ip = registry_host.split(":", 1)[0]
    cidrs = []
    if host_ip.startswith("10."):
        cidrs.append("10.0.0.0/8")
    elif host_ip.startswith("192.168."):
        cidrs.append("192.168.0.0/16")
    elif re.match(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", host_ip):
        cidrs.append("172.16.0.0/12")
    return any(cidr in text for cidr in cidrs)


def verify_registry_transport(ctx: UpReadyContext) -> None:
    if os.getenv("UP_READY_SKIP_REGISTRY_PREFLIGHT", "0") in {"1", "true", "yes"}:
        return
    registry = os.getenv("REGISTRY", "")
    registry_host = registry_host_value(registry) if registry else ""
    if not registry_host:
        return
    if not registry_plain_http_enabled(registry_host, os.getenv("REGISTRY_PLAIN_HTTP", "auto")):
        return
    try:
        response = httpx.get(f"http://{registry_host}/v2/", timeout=2.0)
        reachable = response.status_code < 500
    except httpx.HTTPError:
        reachable = False
    if not reachable:
        warn(f"plain-HTTP registry {registry_host} is not reachable at /v2/ yet")
        return
    if docker_daemon_lists_insecure_registry(registry_host):
        return
    ctx.classify("http: server gave HTTP response to HTTPS client")
    raise UpReadyError(
        "Docker daemon is not configured for plain-HTTP registry "
        f"{registry_host}. Add it to insecure-registries and restart Docker."
    )


def ensure_compose_env_defaults(ctx: UpReadyContext) -> None:
    dotenv = repo_root() / ".env"
    existing_registry = None if os.getenv("REGISTRY") else read_dotenv_value(dotenv, "REGISTRY")
    registry = os.getenv("REGISTRY") or (
        existing_registry
        if existing_registry and not contains_unresolved_placeholder(existing_registry)
        else default_registry_value(ctx.settings.server_ip)
    )
    if contains_unresolved_placeholder(registry):
        raise UpReadyError("REGISTRY resolved to a placeholder; set REGISTRY or SERVER_IP before running up-ready")

    existing_image_tag = None if os.getenv("IMAGE_TAG") else read_dotenv_value(dotenv, "IMAGE_TAG")
    image_tag = os.getenv("IMAGE_TAG") or (
        existing_image_tag
        if existing_image_tag and not contains_unresolved_placeholder(existing_image_tag)
        else "latest"
    )
    if contains_unresolved_placeholder(image_tag):
        raise UpReadyError("IMAGE_TAG resolved to a placeholder; set IMAGE_TAG before running up-ready")
    os.environ["REGISTRY"] = registry
    os.environ["IMAGE_TAG"] = image_tag


def require_dotenv_value_resolved(key: str) -> None:
    value = read_dotenv_value(repo_root() / ".env", key)
    if not value:
        raise UpReadyError(f"{key} is missing or empty in .env after scripts/gen-secrets env")
    if contains_unresolved_placeholder(value):
        raise UpReadyError(f"{key} still contains an unresolved placeholder in .env after scripts/gen-secrets env")


def validate_materialized_env() -> None:
    dotenv = repo_root() / ".env"
    if not dotenv.is_file():
        raise UpReadyError(".env missing after scripts/gen-secrets env")
    for key in REQUIRED_DOTENV_KEYS:
        require_dotenv_value_resolved(key)
    dotenv_registry = read_dotenv_value(dotenv, "REGISTRY")
    if dotenv_registry != os.getenv("REGISTRY"):
        raise UpReadyError(f".env REGISTRY={dotenv_registry} does not match runtime REGISTRY={os.getenv('REGISTRY')}")
    dotenv_image_tag = read_dotenv_value(dotenv, "IMAGE_TAG")
    if dotenv_image_tag != os.getenv("IMAGE_TAG"):
        raise UpReadyError(
            f".env IMAGE_TAG={dotenv_image_tag} does not match runtime IMAGE_TAG={os.getenv('IMAGE_TAG')}"
        )


def gen_secrets(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return shell.run([repo_root() / "scripts" / "gen-secrets", *args], check=check, capture=True)


def materialize_secret_env(ctx: UpReadyContext) -> None:
    ensure_compose_env_defaults(ctx)
    gen_secrets("env")
    validate_materialized_env()


def ensure_secret_bootstrap(ctx: UpReadyContext) -> None:
    step("S00", "secret_bootstrap: checking generated secrets")
    if gen_secrets("check", check=False).returncode == 0:
        materialize_secret_env(ctx)
        step("S00", f"secret_bootstrap: .env materialized (REGISTRY={os.getenv('REGISTRY')} IMAGE_TAG={os.getenv('IMAGE_TAG')})")
        return
    if (repo_root() / "secrets" / "ONE_TIME_TOKENS").is_file():
        try:
            materialize_secret_env(ctx)
        except UpReadyError:
            pass
        gen_secrets("check", check=False)
        raise UpReadyError("Consume secrets/ONE_TIME_TOKENS, delete it, then rerun up-ready")

    step("S00", "secret_bootstrap: repairing generated secrets")
    if gen_secrets("repair", check=False).returncode == 0:
        materialize_secret_env(ctx)
        step("S00", "secret_bootstrap: repaired generated secrets")
        return

    step("S00", "secret_bootstrap: generating missing secrets")
    shell.run([repo_root() / "scripts" / "gen-secrets", "generate"], check=True)
    materialize_secret_env(ctx)
    if gen_secrets("check", check=False).returncode != 0:
        raise UpReadyError("Consume secrets/ONE_TIME_TOKENS, delete it, then rerun up-ready")
