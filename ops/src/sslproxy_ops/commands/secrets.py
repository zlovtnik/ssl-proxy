from __future__ import annotations

import os

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root


ELIXIR_REQUIRES = [
    "lib/wg_key_rotator/error.ex",
    "lib/wg_key_rotator/atomic_file.ex",
    "lib/wg_key_rotator/command.ex",
    "lib/wg_key_rotator/config.ex",
    "lib/wg_key_rotator/keygen.ex",
    "lib/wg_key_rotator/peer_config.ex",
    "lib/wg_key_rotator/message.ex",
    "lib/wg_key_rotator/json.ex",
    "lib/wg_key_rotator/health.ex",
    "lib/wg_key_rotator/deploy.ex",
    "lib/wg_key_rotator/waha_client.ex",
    "lib/wg_key_rotator/rotation.ex",
    "lib/wg_key_rotator/secrets.ex",
    "lib/wg_key_rotator.ex",
    "lib/wg_key_rotator/cli.ex",
]


def normalize_args(args: list[str]) -> list[str]:
    if not args:
        return ["generate"]
    if args[0] in {"--dry-run", "--force"}:
        return ["generate", *args]
    if args[0] not in {"generate", "check", "repair", "env"}:
        raise ValueError(
            "Usage: scripts/gen-secrets [--force] [--dry-run] | generate | check | repair | env"
        )
    return args


def run(args: list[str]) -> int:
    args = normalize_args(args)
    rotator_dir = repo_root() / "apps" / "wg-key-rotator"
    command = ["elixir"]
    for required in ELIXIR_REQUIRES:
        command.extend(["-r", required])
    command.extend(
        [
            "-e",
            'WgKeyRotator.CLI.main(["secrets" | System.argv()])',
            "--",
            *args,
        ]
    )
    env = {**os.environ, "ROTATOR_REPO_ROOT": os.getenv("ROTATOR_REPO_ROOT", str(repo_root()))}
    completed = shell.run(command, cwd=rotator_dir, env=env, check=False)
    return completed.returncode
