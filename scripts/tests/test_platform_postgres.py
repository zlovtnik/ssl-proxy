from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from platform_postgres import (  # noqa: E402
    MaintenanceError,
    ROLLOUT_TARGETS,
    Runtime,
    clean_password,
    load_contract,
    parse_userlist,
    replace_userlist_password,
    require_confirmation,
    validate_private_file,
    verify_deployment_rollouts,
)


class PlatformPostgresTest(unittest.TestCase):
    def test_rollout_verification_waits_for_new_generation(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.commands: list[tuple[str, ...]] = []

            def run(self, arguments, **_kwargs):
                command = tuple(arguments)
                self.commands.append(command)
                if "jsonpath={.metadata.generation}" in command:
                    return SimpleNamespace(stdout=b"2")
                return SimpleNamespace(stdout=b"")

        runtime = Runtime(
            contract_path=Path("contract"),
            compose_file=Path("compose"),
            container="postgres",
            data_volume="data",
            secret_volume="secrets",
            tls_volume="tls",
            vault_mount="secret",
            vault_prefix="ssl-proxy/prod",
            repository_root=REPOSITORY_ROOT,
            health_timeout=1,
            kubectl="kubectl",
            kube_context="test-context",
            kubernetes_namespace="prod-ssl-proxy",
            rollout_timeout=5,
        )
        runner = FakeRunner()

        verify_deployment_rollouts(runner, runtime, {"consumer": 1})

        self.assertEqual(2, len(runner.commands))
        self.assertIn("get", runner.commands[0])
        self.assertIn("rollout", runner.commands[1])
        self.assertIn("deployment/consumer", runner.commands[1])

    def test_rotation_targets_cover_every_postgres_role(self) -> None:
        self.assertEqual(
            {
                "atheros_search_runtime",
                "keycloak_runtime",
                "octopus_runtime",
                "schema_migrator_runtime",
                "schema_owner",
            },
            set(ROLLOUT_TARGETS),
        )
        self.assertEqual((), ROLLOUT_TARGETS["schema_owner"])
        self.assertIn(
            "postgres-pgbouncer", ROLLOUT_TARGETS["octopus_runtime"]
        )

    def test_repository_contract_loads_verified_tls_and_pinned_image(self) -> None:
        contract = load_contract(
            REPOSITORY_ROOT / "cyber-stack/platform-input-contract.yaml"
        )
        self.assertEqual("verify-full", contract.tls_mode)
        self.assertEqual(contract.host, contract.tls_server_name)
        self.assertIn("@sha256:", contract.image)

    def test_confirmation_is_exact(self) -> None:
        require_confirmation("RESET-volume", "RESET-volume")
        for value in (None, "reset-volume", "RESET-other"):
            with self.subTest(value=value), self.assertRaises(MaintenanceError):
                require_confirmation(value, "RESET-volume")

    def test_passwords_must_be_non_empty_single_line(self) -> None:
        self.assertEqual(b"secret", clean_password(b"secret\n", "password"))
        for value in (b"", b"\n", b"one\ntwo", b"bad\0value"):
            with self.subTest(value=value), self.assertRaises(MaintenanceError):
                clean_password(value, "password")

    def test_userlist_rotation_preserves_other_entries_and_comments(self) -> None:
        original = (
            b'# generated\n"octopus_runtime" "old"\n'
            b'"atheros_search_runtime" "search"\n'
        )
        rotated = replace_userlist_password(original, "octopus_runtime", b"new")
        self.assertEqual(
            {
                "octopus_runtime": "new",
                "atheros_search_runtime": "search",
            },
            parse_userlist(rotated),
        )
        self.assertTrue(rotated.startswith(b"# generated\n"))

    def test_userlist_rejects_duplicate_or_missing_account(self) -> None:
        with self.assertRaises(MaintenanceError):
            parse_userlist(b'"octopus_runtime" "one"\n"octopus_runtime" "two"\n')
        with self.assertRaises(MaintenanceError):
            replace_userlist_password(
                b'"atheros_search_runtime" "search"\n',
                "octopus_runtime",
                b"new",
            )

    def test_private_key_permissions_are_restrictive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.key"
            path.write_text("key", encoding="utf-8")
            os.chmod(path, 0o600)
            validate_private_file(path, "TLS private key")
            os.chmod(path, 0o640)
            with self.assertRaises(MaintenanceError):
                validate_private_file(path, "TLS private key")


if __name__ == "__main__":
    unittest.main()
