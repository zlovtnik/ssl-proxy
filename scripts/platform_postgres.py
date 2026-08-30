#!/usr/bin/env python3
"""Safely maintain the external Wiretrap PostgreSQL prerequisite.

This tool deliberately does not write Kubernetes objects. Vault remains the
credential source of truth and platform-sync remains the only Kubernetes
writer. Destructive operations require an exact confirmation token.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = REPOSITORY_ROOT / "cyber-stack/platform-input-contract.yaml"
DEFAULT_COMPOSE = Path.home() / ".local/share/ssl-proxy-platform/compose.yaml"
DEFAULT_CONTAINER = "ssl-proxy-platform-postgres"
DEFAULT_DATA_VOLUME = "ssl-proxy-platform-postgres-data"
DEFAULT_SECRET_VOLUME = "ssl-proxy-platform-postgres-secrets"
DEFAULT_TLS_VOLUME = "ssl-proxy-platform-postgres-tls"
DEFAULT_VAULT_MOUNT = "secret"
DEFAULT_VAULT_PREFIX = "ssl-proxy/prod"
HELPER_IMAGE = "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"


class MaintenanceError(RuntimeError):
    """A safe maintenance precondition or operation failed."""


@dataclass(frozen=True)
class Account:
    secret_name: str
    role: str
    file_name: str
    pgbouncer: bool


ACCOUNTS = (
    Account("postgres-schema-owner", "schema_owner", "schema_owner.password", False),
    Account("postgres-octopus", "octopus_runtime", "octopus_runtime.password", True),
    Account(
        "postgres-atheros-search",
        "atheros_search_runtime",
        "atheros_search_runtime.password",
        True,
    ),
    Account(
        "postgres-schema-migrator",
        "schema_migrator_runtime",
        "schema_migrator_runtime.password",
        True,
    ),
    Account("postgres-keycloak", "keycloak_runtime", "keycloak_runtime.password", False),
)
ACCOUNTS_BY_ROLE = {account.role: account for account in ACCOUNTS}


@dataclass(frozen=True)
class PostgresContract:
    image: str
    host: str
    port: int
    database: str
    tls_mode: str
    tls_server_name: str


@dataclass(frozen=True)
class Runtime:
    contract_path: Path
    compose_file: Path
    container: str
    data_volume: str
    secret_volume: str
    tls_volume: str
    vault_mount: str
    vault_prefix: str
    repository_root: Path
    health_timeout: int


class Runner:
    def run(
        self,
        arguments: Sequence[str],
        *,
        input_data: bytes | None = None,
        capture: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            list(arguments),
            input=input_data,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            if not detail:
                detail = "command exited non-zero"
            raise MaintenanceError(f"{arguments[0]} failed: {detail}")
        return completed


def load_contract(path: Path) -> PostgresContract:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise MaintenanceError(f"contract is missing: {path}") from error
    except yaml.YAMLError as error:
        raise MaintenanceError(f"cannot parse contract {path}: {error}") from error
    try:
        postgres = document["spec"]["bootstrap"]["postgres"]
        endpoint = postgres["endpoint"]
        contract = PostgresContract(
            image=str(postgres["image"]),
            host=str(endpoint["host"]),
            port=int(endpoint["port"]),
            database=str(endpoint["database"]),
            tls_mode=str(endpoint["tlsMode"]),
            tls_server_name=str(endpoint["tlsServerName"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise MaintenanceError(f"contract PostgreSQL bootstrap is invalid: {error}") from error
    if contract.tls_mode != "verify-full":
        raise MaintenanceError("contract PostgreSQL TLS mode must be verify-full")
    if contract.host != contract.tls_server_name:
        raise MaintenanceError("contract PostgreSQL host and TLS server name must match")
    if "@sha256:" not in contract.image:
        raise MaintenanceError("contract PostgreSQL image must be digest-pinned")
    return contract


def require_confirmation(actual: str | None, expected: str) -> None:
    if actual != expected:
        raise MaintenanceError(f"refusing destructive operation; pass --confirm {expected}")


def require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise MaintenanceError(f"required command(s) not found: {', '.join(missing)}")


def clean_password(value: bytes, label: str) -> bytes:
    cleaned = value.rstrip(b"\r\n")
    if not cleaned or any(character in cleaned for character in (b"\r", b"\n", b"\0")):
        raise MaintenanceError(f"{label} must be non-empty and single-line")
    return cleaned


def vault_path(runtime: Runtime, secret_name: str) -> str:
    return f"{runtime.vault_prefix.rstrip('/')}/{secret_name}"


def vault_read(
    runner: Runner,
    runtime: Runtime,
    secret_name: str,
    field: str,
    *,
    single_line: bool,
) -> bytes:
    result = runner.run(
        (
            "vault",
            "kv",
            "get",
            f"-mount={runtime.vault_mount}",
            f"-field={field}",
            vault_path(runtime, secret_name),
        )
    )
    if single_line:
        return clean_password(result.stdout, f"Vault {secret_name}/{field}")
    value = result.stdout.rstrip(b"\r\n")
    if not value:
        raise MaintenanceError(f"Vault {secret_name}/{field} is empty")
    return value


def vault_patch(
    runner: Runner,
    runtime: Runtime,
    secret_name: str,
    field: str,
    value: bytes,
) -> None:
    runner.run(
        (
            "vault",
            "kv",
            "patch",
            f"-mount={runtime.vault_mount}",
            vault_path(runtime, secret_name),
            f"{field}=-",
        ),
        input_data=value,
    )


def postgres_ids(runner: Runner, runtime: Runtime, contract: PostgresContract) -> tuple[int, int]:
    inspect = runner.run(
        ("docker", "inspect", runtime.container), check=False
    )
    running = False
    if inspect.returncode == 0:
        try:
            info = json.loads(inspect.stdout)
            running = (
                isinstance(info, list)
                and info
                and isinstance(info[0], dict)
                and info[0].get("State", {}).get("Running") is True
            )
        except (json.JSONDecodeError, IndexError):
            pass
    if running:
        uid = runner.run(("docker", "exec", runtime.container, "id", "-u", "postgres"))
        gid = runner.run(("docker", "exec", runtime.container, "id", "-g", "postgres"))
    else:
        uid = runner.run(
            ("docker", "run", "--rm", "--entrypoint", "id", contract.image, "-u", "postgres")
        )
        gid = runner.run(
            ("docker", "run", "--rm", "--entrypoint", "id", contract.image, "-g", "postgres")
        )
    try:
        return int(uid.stdout.strip()), int(gid.stdout.strip())
    except ValueError as error:
        raise MaintenanceError("could not resolve PostgreSQL container UID/GID") from error


def write_volume_secret(
    runner: Runner,
    runtime: Runtime,
    file_name: str,
    value: bytes,
    uid: int,
    gid: int,
) -> None:
    if file_name not in {account.file_name for account in ACCOUNTS}:
        raise MaintenanceError(f"unsupported PostgreSQL secret file: {file_name}")
    helper = r"""
set -eu
target=/secrets/$TARGET_NAME
temporary=/secrets/.$TARGET_NAME.$$
trap 'rm -f "$temporary"' EXIT
tr -d '\r\n' >"$temporary"
[ -s "$temporary" ]
chown "$POSTGRES_UID:$POSTGRES_GID" "$temporary"
chmod 0400 "$temporary"
mv "$temporary" "$target"
trap - EXIT
""".strip()
    runner.run(
        (
            "docker",
            "run",
            "--rm",
            "-i",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--cap-add=CHOWN",
            "--cap-add=FOWNER",
            "--security-opt=no-new-privileges",
            "-e",
            f"TARGET_NAME={file_name}",
            "-e",
            f"POSTGRES_UID={uid}",
            "-e",
            f"POSTGRES_GID={gid}",
            "--mount",
            f"type=volume,src={runtime.secret_volume},dst=/secrets",
            HELPER_IMAGE,
            "sh",
            "-eu",
            "-c",
            helper,
        ),
        input_data=value,
    )


def stage_accounts(
    runner: Runner,
    runtime: Runtime,
    contract: PostgresContract,
    accounts: Sequence[Account] = ACCOUNTS,
) -> None:
    values = {
        account: vault_read(
            runner, runtime, account.secret_name, "password", single_line=True
        )
        for account in accounts
    }
    uid, gid = postgres_ids(runner, runtime, contract)
    for account, value in values.items():
        write_volume_secret(runner, runtime, account.file_name, value, uid, gid)
        print(f"staged {account.file_name} from Vault")


def mounted_data_volume(runner: Runner, runtime: Runtime) -> str:
    result = runner.run(
        (
            "docker",
            "inspect",
            runtime.container,
            "--format",
            '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}',
        )
    )
    return result.stdout.decode("utf-8", errors="replace").strip()


def assert_exact_mount(runner: Runner, runtime: Runtime) -> None:
    mounted = mounted_data_volume(runner, runtime)
    if mounted != runtime.data_volume:
        raise MaintenanceError(
            f"{runtime.container} mounts {mounted!r}, expected {runtime.data_volume!r}"
        )


def compose(runner: Runner, runtime: Runtime, *arguments: str) -> None:
    runner.run(
        ("docker", "compose", "-f", str(runtime.compose_file), *arguments),
        capture=False,
    )


def wait_for_health(runner: Runner, runtime: Runtime) -> None:
    deadline = time.monotonic() + runtime.health_timeout
    while time.monotonic() < deadline:
        result = runner.run(
            (
                "docker",
                "inspect",
                runtime.container,
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
            ),
            check=False,
        )
        status_value = result.stdout.decode("utf-8", errors="replace").strip()
        if status_value == "healthy":
            print("PostgreSQL is healthy")
            return
        if status_value in {"dead", "exited"}:
            raise MaintenanceError(f"PostgreSQL entered state {status_value}")
        time.sleep(2)
    raise MaintenanceError("PostgreSQL did not become healthy before the timeout")


def write_env_file(values: Mapping[str, bytes | str]) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix="ssl-proxy-postgres-", suffix=".env")
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            for name, raw_value in values.items():
                value = raw_value.encode("utf-8") if isinstance(raw_value, str) else raw_value
                clean_password(value, name)
                handle.write(name.encode("ascii") + b"=" + value + b"\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def schema_environment(contract: PostgresContract, owner_password: bytes) -> dict[str, bytes | str]:
    return {
        "POSTGRES_HOST": contract.host,
        "POSTGRES_PORT": str(contract.port),
        "POSTGRES_DATABASE": contract.database,
        "POSTGRES_SCHEMA_OWNER_USER": "schema_owner",
        "POSTGRES_SCHEMA_OWNER_PASSWORD": owner_password,
        "POSTGRES_OCTOPUS_ACCOUNT": "octopus_runtime",
        "POSTGRES_ATHEROS_SEARCH_ACCOUNT": "atheros_search_runtime",
        "POSTGRES_SCHEMA_MIGRATOR_ACCOUNT": "schema_migrator_runtime",
        "POSTGRES_KEYCLOAK_ACCOUNT": "keycloak_runtime",
        "PGSSLMODE": contract.tls_mode,
        "POSTGRES_SSL_SERVER_NAME": contract.tls_server_name,
        "PGSSLROOTCERT": "/var/run/postgres-tls/ca.crt",
    }


def apply_schema(runner: Runner, runtime: Runtime, contract: PostgresContract) -> None:
    entrypoint = runtime.repository_root / "k8s/postgres-schema-executor/entrypoint.sh"
    schema_root = runtime.repository_root / "sql/postgres"
    if not entrypoint.is_file() or not schema_root.is_dir():
        raise MaintenanceError("canonical PostgreSQL schema executor sources are missing")
    owner_password = vault_read(
        runner, runtime, "postgres-schema-owner", "password", single_line=True
    )
    env_file = write_env_file(schema_environment(contract, owner_password))
    try:
        runner.run(
            (
                "docker",
                "run",
                "--rm",
                "--user",
                "65532:65532",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=256",
                "--memory=1g",
                "--cpus=2",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=67108864",
                "--env-file",
                str(env_file),
                "--mount",
                f"type=bind,src={schema_root},dst=/workspace/sql/postgres,readonly",
                "--mount",
                f"type=bind,src={entrypoint},dst=/usr/local/bin/postgres-runtime-schema,readonly",
                "--mount",
                f"type=volume,src={runtime.tls_volume},dst=/var/run/postgres-tls,readonly",
                "--entrypoint",
                "/usr/local/bin/postgres-runtime-schema",
                contract.image,
            ),
            capture=False,
        )
    finally:
        env_file.unlink(missing_ok=True)
    print("canonical PostgreSQL schemas applied")


def reset_database(
    runner: Runner,
    runtime: Runtime,
    contract: PostgresContract,
    confirmation: str | None,
) -> None:
    expected = f"RESET-{runtime.data_volume}"
    require_confirmation(confirmation, expected)
    if not runtime.compose_file.is_file():
        raise MaintenanceError(f"Compose file is missing: {runtime.compose_file}")
    assert_exact_mount(runner, runtime)
    stage_accounts(runner, runtime, contract)
    compose(runner, runtime, "stop", "postgres")
    compose(runner, runtime, "rm", "-f", "postgres")
    references = runner.run(
        ("docker", "ps", "-aq", "--filter", f"volume={runtime.data_volume}")
    ).stdout.strip()
    if references:
        raise MaintenanceError(f"a container still references {runtime.data_volume}")
    runner.run(("docker", "volume", "rm", runtime.data_volume))
    runner.run(("docker", "volume", "create", runtime.data_volume))
    compose(runner, runtime, "up", "-d", "postgres")
    wait_for_health(runner, runtime)
    apply_schema(runner, runtime, contract)
    print("database reset complete; run platform-sync before rolling consumers")


def parse_userlist(contents: bytes) -> dict[str, str]:
    users: dict[str, str] = {}
    for number, raw_line in enumerate(contents.decode("utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            fields = shlex.split(line, posix=True)
        except ValueError as error:
            raise MaintenanceError(f"PgBouncer userlist line {number} is invalid") from error
        if len(fields) != 2 or not all(fields):
            raise MaintenanceError(f"PgBouncer userlist line {number} is invalid")
        if fields[0] in users:
            raise MaintenanceError(f"PgBouncer userlist duplicates {fields[0]}")
        users[fields[0]] = fields[1]
    return users


def replace_userlist_password(contents: bytes, role: str, password: bytes) -> bytes:
    password_text = clean_password(password, "rotated password").decode("utf-8")
    users = parse_userlist(contents)
    if role not in users:
        raise MaintenanceError(f"PgBouncer userlist does not contain {role}")
    output: list[str] = []
    for raw_line in contents.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            output.append(raw_line)
            continue
        fields = shlex.split(line, posix=True)
        if fields[0] == role:
            output.append(f'"{role}" "{password_text}"')
        else:
            output.append(raw_line)
    return ("\n".join(output) + "\n").encode("utf-8")


def set_database_password(
    runner: Runner,
    runtime: Runtime,
    account: Account,
    password: bytes,
) -> None:
    role_check = runner.run(
        (
            "docker",
            "exec",
            runtime.container,
            "sh",
            "-eu",
            "-c",
            "PGPASSWORD=$(tr -d '\\r\\n' </run/platform-secrets/platform_admin.password); "
            "export PGPASSWORD; exec psql --no-psqlrc --username platform_admin --dbname sync "
            "--tuples-only --no-align --command=\"SELECT 1 FROM pg_roles WHERE rolname = '"
            + account.role
            + "'\"",
        )
    )
    if role_check.stdout.strip() != b"1":
        raise MaintenanceError(f"PostgreSQL role {account.role} does not exist")
    env_file = write_env_file({"ROTATED_PASSWORD": password})
    sql = (
        b"\\getenv rotated_password ROTATED_PASSWORD\n"
        b"SET log_statement = 'none';\n"
        b"SET password_encryption = 'scram-sha-256';\n"
        + f"ALTER ROLE {account.role} PASSWORD :'rotated_password';\n".encode("ascii")
    )
    try:
        runner.run(
            (
                "docker",
                "exec",
                "--env-file",
                str(env_file),
                "-i",
                runtime.container,
                "sh",
                "-eu",
                "-c",
                "PGPASSWORD=$(tr -d '\\r\\n' </run/platform-secrets/platform_admin.password); "
                "export PGPASSWORD; exec psql --no-psqlrc --set=ON_ERROR_STOP=1 "
                "--username platform_admin --dbname sync",
            ),
            input_data=sql,
        )
    finally:
        env_file.unlink(missing_ok=True)


def verify_database_login(
    runner: Runner,
    runtime: Runtime,
    contract: PostgresContract,
    account: Account,
    password: bytes,
) -> None:
    env_file = write_env_file({"PGPASSWORD": password})
    try:
        runner.run(
            (
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--env-file",
                str(env_file),
                "--mount",
                f"type=volume,src={runtime.tls_volume},dst=/var/run/postgres-tls,readonly",
                "--entrypoint",
                "psql",
                contract.image,
                f"host={contract.host}",
                f"port={contract.port}",
                f"dbname={contract.database}",
                f"user={account.role}",
                f"sslmode={contract.tls_mode}",
                "sslrootcert=/var/run/postgres-tls/ca.crt",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--command=select current_user",
            )
        )
    finally:
        env_file.unlink(missing_ok=True)


def rotate_password(
    runner: Runner,
    runtime: Runtime,
    contract: PostgresContract,
    role: str,
    confirmation: str | None,
) -> None:
    account = ACCOUNTS_BY_ROLE.get(role)
    if account is None:
        raise MaintenanceError(f"unsupported PostgreSQL role: {role}")
    require_confirmation(confirmation, f"ROTATE-{role}")
    old_password = vault_read(
        runner, runtime, account.secret_name, "password", single_line=True
    )
    original_userlist: bytes | None = None
    rotated_userlist: bytes | None = None
    if account.pgbouncer:
        original_userlist = vault_read(
            runner,
            runtime,
            "pgbouncer-runtime-users",
            "userlist.txt",
            single_line=False,
        )
        users = parse_userlist(original_userlist)
        if users.get(role, "").encode("utf-8") != old_password:
            raise MaintenanceError(
                f"PgBouncer userlist and Vault password already differ for {role}"
            )
    new_password = secrets.token_hex(32).encode("ascii")
    if original_userlist is not None:
        rotated_userlist = replace_userlist_password(original_userlist, role, new_password)

    database_changed = False
    vault_account_changed = False
    vault_userlist_changed = False
    try:
        set_database_password(runner, runtime, account, new_password)
        database_changed = True
        verify_database_login(runner, runtime, contract, account, new_password)
        vault_patch(runner, runtime, account.secret_name, "password", new_password)
        vault_account_changed = True
        if rotated_userlist is not None:
            vault_patch(
                runner,
                runtime,
                "pgbouncer-runtime-users",
                "userlist.txt",
                rotated_userlist,
            )
            vault_userlist_changed = True
        uid, gid = postgres_ids(runner, runtime, contract)
        write_volume_secret(
            runner, runtime, account.file_name, new_password, uid, gid
        )
    except Exception as primary_error:
        rollback_errors: list[str] = []
        if vault_userlist_changed and original_userlist is not None:
            try:
                vault_patch(
                    runner,
                    runtime,
                    "pgbouncer-runtime-users",
                    "userlist.txt",
                    original_userlist,
                )
            except Exception as error:  # pragma: no cover - integration failure path
                rollback_errors.append(f"PgBouncer Vault rollback failed: {error}")
        if vault_account_changed:
            try:
                vault_patch(
                    runner, runtime, account.secret_name, "password", old_password
                )
            except Exception as error:  # pragma: no cover - integration failure path
                rollback_errors.append(f"account Vault rollback failed: {error}")
        if database_changed:
            try:
                set_database_password(runner, runtime, account, old_password)
            except Exception as error:  # pragma: no cover - integration failure path
                rollback_errors.append(f"database rollback failed: {error}")
        detail = "; ".join(rollback_errors)
        if detail:
            raise MaintenanceError(f"rotation failed: {primary_error}; {detail}") from primary_error
        raise MaintenanceError(f"rotation failed and was rolled back: {primary_error}") from primary_error
    print(f"rotated {role}; run platform-sync, then verify consumers before revoking old Vault versions")


def validate_private_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise MaintenanceError(f"{label} must be a regular non-symlink file: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise MaintenanceError(f"{label} permissions must not grant group/world access: {path}")


def validate_tls_candidate(
    runner: Runner,
    ca_path: Path,
    certificate_path: Path,
    key_path: Path,
    server_name: str,
    minimum_valid_seconds: int,
) -> None:
    validate_private_file(key_path, "TLS private key")
    for path, label in ((ca_path, "TLS CA"), (certificate_path, "TLS certificate")):
        if path.is_symlink() or not path.is_file():
            raise MaintenanceError(f"{label} must be a regular non-symlink file: {path}")
    runner.run(("openssl", "verify", "-CAfile", str(ca_path), str(certificate_path)))
    runner.run(
        (
            "openssl",
            "x509",
            "-in",
            str(certificate_path),
            "-checkend",
            str(minimum_valid_seconds),
            "-noout",
        )
    )
    try:
        ipaddress.ip_address(server_name)
        identity_flag = "-checkip"
    except ValueError:
        identity_flag = "-checkhost"
    runner.run(
        (
            "openssl",
            "x509",
            "-in",
            str(certificate_path),
            identity_flag,
            server_name,
            "-noout",
        )
    )
    certificate_key = runner.run(
        ("openssl", "x509", "-in", str(certificate_path), "-pubkey", "-noout")
    ).stdout
    private_key = runner.run(
        ("openssl", "pkey", "-in", str(key_path), "-pubout")
    ).stdout
    if certificate_key != private_key:
        raise MaintenanceError("TLS certificate and private key do not match")
    print("TLS candidate is valid for verified-full activation")


def check_runtime(runner: Runner, runtime: Runtime, contract: PostgresContract) -> None:
    require_tools("docker", "vault", "openssl")
    if not runtime.compose_file.is_file():
        raise MaintenanceError(f"Compose file is missing: {runtime.compose_file}")
    assert_exact_mount(runner, runtime)
    runner.run(("vault", "status", "-format=json"))
    for account in ACCOUNTS:
        vault_read(runner, runtime, account.secret_name, "password", single_line=True)
    print(f"PostgreSQL contract: {contract.host}:{contract.port}/{contract.database} {contract.tls_mode}")
    print(f"container {runtime.container} mounts expected data volume {runtime.data_volume}")
    print("all five Vault account credentials are readable (values suppressed)")


def runtime_from_args(arguments: argparse.Namespace) -> Runtime:
    return Runtime(
        contract_path=arguments.contract.resolve(),
        compose_file=arguments.compose_file.expanduser().resolve(),
        container=arguments.container,
        data_volume=arguments.data_volume,
        secret_volume=arguments.secret_volume,
        tls_volume=arguments.tls_volume,
        vault_mount=arguments.vault_mount,
        vault_prefix=arguments.vault_prefix.strip("/"),
        repository_root=arguments.repository_root.resolve(),
        health_timeout=arguments.health_timeout,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    result.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE)
    result.add_argument("--container", default=DEFAULT_CONTAINER)
    result.add_argument("--data-volume", default=DEFAULT_DATA_VOLUME)
    result.add_argument("--secret-volume", default=DEFAULT_SECRET_VOLUME)
    result.add_argument("--tls-volume", default=DEFAULT_TLS_VOLUME)
    result.add_argument("--vault-mount", default=DEFAULT_VAULT_MOUNT)
    result.add_argument("--vault-prefix", default=DEFAULT_VAULT_PREFIX)
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument("--health-timeout", type=int, default=120)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="run read-only prerequisite checks")
    commands.add_parser("stage-secrets", help="stage all five Vault passwords in the Docker secret volume")
    reset = commands.add_parser("reset", help="delete and recreate the exact PostgreSQL data volume")
    reset.add_argument("--confirm")
    rotate = commands.add_parser("rotate-password", help="rotate one PostgreSQL account with rollback")
    rotate.add_argument("--role", choices=tuple(ACCOUNTS_BY_ROLE), required=True)
    rotate.add_argument("--confirm")
    tls = commands.add_parser("validate-tls", help="validate a TLS candidate without installing it")
    tls.add_argument("--ca", type=Path, required=True)
    tls.add_argument("--certificate", type=Path, required=True)
    tls.add_argument("--key", type=Path, required=True)
    tls.add_argument("--server-name")
    tls.add_argument("--minimum-valid-seconds", type=int, default=604800)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    runtime = runtime_from_args(arguments)
    runner = Runner()
    try:
        contract = load_contract(runtime.contract_path)
        if arguments.command == "check":
            check_runtime(runner, runtime, contract)
        elif arguments.command == "stage-secrets":
            require_tools("docker", "vault")
            stage_accounts(runner, runtime, contract)
        elif arguments.command == "reset":
            require_tools("docker", "vault")
            reset_database(runner, runtime, contract, arguments.confirm)
        elif arguments.command == "rotate-password":
            require_tools("docker", "vault")
            rotate_password(
                runner,
                runtime,
                contract,
                arguments.role,
                arguments.confirm,
            )
        elif arguments.command == "validate-tls":
            require_tools("openssl")
            validate_tls_candidate(
                runner,
                arguments.ca.resolve(),
                arguments.certificate.resolve(),
                arguments.key.resolve(),
                arguments.server_name or contract.tls_server_name,
                arguments.minimum_valid_seconds,
            )
        else:  # pragma: no cover - argparse guarantees a known command.
            raise MaintenanceError(f"unsupported command: {arguments.command}")
    except MaintenanceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
