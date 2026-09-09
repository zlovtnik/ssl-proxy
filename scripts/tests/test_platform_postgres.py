from __future__ import annotations

import os
import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from platform_postgres import (  # noqa: E402
    MaintenanceError,
    ACCOUNTS_BY_ROLE,
    RELOADER_ANNOTATION,
    ROLLOUT_TARGETS,
    Runner,
    Runtime,
    backup_keycloak,
    clean_password,
    ensure_role_search_paths,
    load_contract,
    parse_userlist,
    replace_userlist_password,
    require_confirmation,
    reset_database,
    validate_private_file,
    verify_deployment_rollouts,
)


class PlatformPostgresTest(unittest.TestCase):
    def test_identity_backup_refuses_connected_clients(self) -> None:
        from unittest.mock import Mock

        runner = Mock()
        runner.run.return_value = SimpleNamespace(stdout=b"2\n")
        with self.assertRaisesRegex(MaintenanceError, "clients are still connected"):
            backup_keycloak(runner, SimpleNamespace(container="postgres"),
                            SimpleNamespace(database="sync"))
        self.assertEqual(runner.run.call_count, 1)

    def test_identity_backup_rejects_invalid_archive_and_saves_private_valid_archive(self) -> None:
        from unittest.mock import Mock

        runtime = SimpleNamespace(container="postgres")
        contract = SimpleNamespace(database="sync")
        runner = Mock()
        runner.run.side_effect = [SimpleNamespace(stdout=b"0"), SimpleNamespace(stdout=b"")]
        with self.assertRaisesRegex(MaintenanceError, "not a PostgreSQL custom archive"):
            backup_keycloak(runner, runtime, contract)
        runner.run.side_effect = [SimpleNamespace(stdout=b"0"), SimpleNamespace(stdout=b"PGDMPtest")]
        with tempfile.TemporaryDirectory() as directory, patch(
            "platform_postgres.Path.home", return_value=Path(directory)
        ):
            backup = backup_keycloak(runner, runtime, contract)
            self.assertEqual(backup.read_bytes(), b"PGDMPtest")
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(backup.parent.stat().st_mode & 0o777, 0o700)

    def test_reset_configures_canonical_role_search_paths_as_platform_admin(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.command: tuple[str, ...] | None = None
                self.input_data: bytes | None = None

            def run(self, arguments, *, input_data=None, **_kwargs):
                self.command = tuple(arguments)
                self.input_data = input_data
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
            kube_context=None,
            kubernetes_namespace="prod-ssl-proxy",
            rollout_timeout=5,
        )
        contract = load_contract(
            REPOSITORY_ROOT / "cyber-stack/platform-input-contract.yaml"
        )
        runner = FakeRunner()

        ensure_role_search_paths(runner, runtime, contract)

        self.assertIsNotNone(runner.command)
        self.assertIn("platform_admin.password", runner.command[-1])
        self.assertEqual(
            (
                'ALTER ROLE "octopus_runtime" IN DATABASE "sync" '
                "SET search_path TO octopus_core, atheros_search;\n"
                'ALTER ROLE "atheros_search_runtime" IN DATABASE "sync" '
                "SET search_path TO atheros_search;\n"
                'ALTER ROLE "schema_migrator_runtime" IN DATABASE "sync" '
                "SET search_path TO schema_migrator;\n"
                'ALTER ROLE "keycloak_runtime" IN DATABASE "sync" '
                "SET search_path TO keycloak;\n"
            ).encode("ascii"),
            runner.input_data,
        )

    def test_reset_installs_role_defaults_before_applying_schema(self) -> None:
        class FakeRunner:
            def run(self, _arguments, **_kwargs):
                if "pg_restore" in _arguments:
                    order.append("identity-restore")
                return SimpleNamespace(stdout=b"")

        with tempfile.TemporaryDirectory() as directory:
            compose_file = Path(directory) / "compose.yaml"
            compose_file.write_text("services: {}\n", encoding="utf-8")
            runtime = Runtime(
                contract_path=Path("contract"),
                compose_file=compose_file,
                container="postgres",
                data_volume="data",
                secret_volume="secrets",
                tls_volume="tls",
                vault_mount="secret",
                vault_prefix="ssl-proxy/prod",
                repository_root=REPOSITORY_ROOT,
                health_timeout=1,
                kubectl="kubectl",
                kube_context=None,
                kubernetes_namespace="prod-ssl-proxy",
                rollout_timeout=5,
            )
            contract = load_contract(
                REPOSITORY_ROOT / "cyber-stack/platform-input-contract.yaml"
            )
            order: list[str] = []
            backup = Path(directory) / "identity.dump"
            backup.write_bytes(b"PGDMPtest")

            with (
                patch("platform_postgres.assert_exact_mount"),
                patch("platform_postgres.stage_accounts"),
                patch("platform_postgres.compose"),
                patch("platform_postgres.backup_keycloak", return_value=backup),
                patch(
                    "platform_postgres.wait_for_health",
                    side_effect=lambda *_args: order.append("health"),
                ),
                patch(
                    "platform_postgres.ensure_role_search_paths",
                    side_effect=lambda *_args: order.append("role-defaults"),
                ),
                patch(
                    "platform_postgres.apply_schema",
                    side_effect=lambda *_args: order.append("schema"),
                ),
            ):
                reset_database(FakeRunner(), runtime, contract, "RESET-data")
                self.assertEqual(["health", "role-defaults", "schema"], order)
                order.clear()
                reset_database(FakeRunner(), runtime, contract, "RESET-data",
                               preserve_keycloak=True)

        self.assertEqual(["health", "role-defaults", "schema", "identity-restore"], order)

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


class RolloutVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = SimpleNamespace(
            kubectl="kubectl", kube_context="test-context",
            kubernetes_namespace="prod-ssl-proxy", rollout_timeout=5,
        )
        self.account = ACCOUNTS_BY_ROLE["octopus_runtime"]
        self.now = 0.0
        self.secret_data = {"password": b"new"}
        self.source = {
            "type": "SECRET", "name": "postgres-octopus",
            "namespace": "prod-ssl-proxy",
            "hash": hashlib.sha1(b"password=new").hexdigest(),
        }
        self.deployment = {
            "metadata": {"generation": 2},
            "spec": {"template": {"metadata": {"annotations": {
                RELOADER_ANNOTATION: json.dumps(self.source),
            }}}},
        }
        self.runner = Mock()
        self.runner.run.side_effect = self.run_command
        self.patchers = [
            patch("platform_postgres.time.monotonic", side_effect=lambda: self.now),
            patch("platform_postgres.time.sleep", side_effect=self.advance),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def advance(self, seconds) -> None:
        self.now += seconds

    def run_command(self, arguments, **kwargs):
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 5 - self.now)
        self.advance(0.125)
        if "secret" in arguments:
            result = {"data": {
                key: base64.b64encode(value).decode() for key, value in self.secret_data.items()
            }}
        elif "deployment" in arguments:
            result = self.deployment
        else:
            result = {}
        return subprocess.CompletedProcess(arguments, 0, json.dumps(result).encode(), b"")

    def verify(self, deployment="consumer", previous=(1, "")) -> None:
        verify_deployment_rollouts(
            self.runner, self.runtime, {deployment: previous}, self.account, b"new"
        )

    def assert_no_rollout(self) -> None:
        self.assertFalse(any("rollout" in call.args[0] for call in self.runner.run.call_args_list))

    def test_matching_projection_and_reloader_template_complete_rollout(self) -> None:
        self.verify()
        commands = self.runner.run.call_args_list
        self.assertEqual(3, len(commands))
        self.assertIn("rollout", commands[-1].args[0])
        self.assertIn("deployment/consumer", commands[-1].args[0])
        self.assertIn("test-context", commands[-1].args[0])
        self.assertFalse(commands[-1].kwargs["capture"])

    def test_unrelated_generation_and_template_change_does_not_complete_rollout(self) -> None:
        self.deployment["spec"]["replicas"] = 3
        self.deployment["spec"]["template"]["spec"] = {"containers": [{"image": "new-image"}]}
        self.deployment["spec"]["template"]["metadata"]["annotations"] = {}
        with self.assertRaises(MaintenanceError):
            self.verify()
        self.assert_no_rollout()
        self.assertEqual(5, self.now)

    def test_unrelated_update_can_be_followed_by_valid_reload(self) -> None:
        annotation = self.deployment["spec"]["template"]["metadata"]["annotations"]
        expected = annotation.pop(RELOADER_ANNOTATION)

        def after_poll(seconds):
            self.advance(seconds)
            self.deployment["metadata"]["generation"] = 3
            annotation[RELOADER_ANNOTATION] = expected

        with patch("platform_postgres.time.sleep", side_effect=after_poll):
            self.verify()
        self.assertEqual(5, self.runner.run.call_count)

    def test_stale_secret_cannot_be_verified_by_a_reload(self) -> None:
        self.secret_data["password"] = b"old"
        with self.assertRaises(MaintenanceError):
            self.verify()
        self.assert_no_rollout()

    def test_stale_or_unrelated_reloader_marker_cannot_complete_rollout(self) -> None:
        for field, value in (("hash", "old-hash"), ("name", "other-secret")):
            with self.subTest(field=field):
                self.now = 0
                source = {**self.source, field: value}
                self.deployment["spec"]["template"]["metadata"]["annotations"] = {
                    RELOADER_ANNOTATION: json.dumps(source),
                }
                with self.assertRaises(MaintenanceError):
                    self.verify()
                self.assert_no_rollout()

    def test_unchanged_reloader_marker_cannot_complete_rollout(self) -> None:
        with self.assertRaises(MaintenanceError):
            self.verify(previous=(1, json.dumps(self.source)))
        self.assert_no_rollout()

    def test_pool_verifies_rotated_role_with_concurrent_other_role_update(self) -> None:
        userlist = b'"octopus_runtime" "new"\n"atheros_search_runtime" "also-new"\n'
        self.secret_data = {"userlist.txt": userlist}
        source = {**self.source, "name": "pgbouncer-runtime-users",
                  "hash": hashlib.sha1(b"userlist.txt=" + userlist).hexdigest()}
        self.deployment["spec"]["template"]["metadata"]["annotations"] = {
            RELOADER_ANNOTATION: json.dumps(source),
        }
        self.verify("postgres-pgbouncer")

    def test_blocked_kubernetes_commands_use_remaining_deadline(self) -> None:
        for blocked in ("secret", "deployment", "rollout"):
            with self.subTest(blocked=blocked):
                self.now = 0

                def command(arguments, **kwargs):
                    self.assertLessEqual(kwargs["timeout"], 5 - self.now)
                    if blocked in arguments:
                        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output=b"private")
                    return self.run_command(arguments, **kwargs)

                with patch("platform_postgres.subprocess.run", side_effect=command):
                    with self.assertRaisesRegex(MaintenanceError, "kubectl timed out") as error:
                        verify_deployment_rollouts(
                            Runner(), self.runtime, {"consumer": (1, "")}, self.account, b"new"
                        )
                self.assertNotIn("private", str(error.exception))

    def test_no_command_runs_after_deadline(self) -> None:
        self.runtime.rollout_timeout = 0
        with self.assertRaises(MaintenanceError):
            self.verify()
        self.runner.run.assert_not_called()

    def test_runner_preserves_results_and_nonzero_handling(self) -> None:
        result = subprocess.CompletedProcess(["command"], 1, b"output", b"failed")
        with patch("platform_postgres.subprocess.run", return_value=result) as run:
            self.assertIs(result, Runner().run(["command"], check=False, timeout=0.5))
            self.assertEqual(0.5, run.call_args.kwargs["timeout"])
            with self.assertRaisesRegex(MaintenanceError, "command failed: failed"):
                Runner().run(["command"])


if __name__ == "__main__":
    unittest.main()
