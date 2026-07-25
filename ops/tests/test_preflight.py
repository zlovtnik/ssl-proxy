import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError
from sslproxy_ops.commands.up_ready.preflight import (
    SecretSpec,
    check_api_connectivity,
    check_conflicting_release,
    check_crds,
    check_nodes_ready,
    check_secrets,
    check_service_accounts,
    check_storage_classes,
)
from sslproxy_ops.config import Settings


def _ok(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["kubectl"], returncode=0, stdout=stdout, stderr=stderr)


def _fail(stderr: str = "error") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["kubectl"], returncode=1, stdout="", stderr=stderr)


class PreflightApiConnectivityTest(unittest.TestCase):
    def test_check_api_connectivity_passes_when_cluster_info_succeeds(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(),
        ):
            check_api_connectivity(ctx)

    def test_check_api_connectivity_fails_when_unreachable(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_fail("connection refused"),
            ),
            self.assertRaisesRegex(UpReadyError, "Cannot connect to Kubernetes API"),
        ):
            check_api_connectivity(ctx)


class PreflightNodesReadyTest(unittest.TestCase):
    def test_check_nodes_ready_passes_when_enough_nodes(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "node-1"},
                        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                    },
                    {
                        "metadata": {"name": "node-2"},
                        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                    },
                ]
            }
        )

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(payload),
        ):
            check_nodes_ready(ctx, 2)

    def test_check_nodes_ready_fails_when_insufficient(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "node-1"},
                        "status": {"conditions": [{"type": "Ready", "status": "False"}]},
                    },
                ]
            }
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_ok(payload),
            ),
            self.assertRaisesRegex(UpReadyError, "Insufficient Ready nodes"),
        ):
            check_nodes_ready(ctx, 1)

    def test_check_nodes_ready_fails_on_kubectl_error(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_fail("forbidden"),
            ),
            self.assertRaisesRegex(UpReadyError, "Failed to query nodes"),
        ):
            check_nodes_ready(ctx, 1)


class PreflightStorageClassesTest(unittest.TestCase):
    def test_check_storage_classes_passes_when_present(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "local-path"}},
                    {"metadata": {"name": "standard"}},
                ]
            }
        )

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(payload),
        ):
            check_storage_classes(ctx, ["local-path"])

    def test_check_storage_classes_fails_when_missing(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps({"items": [{"metadata": {"name": "standard"}}]})

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_ok(payload),
            ),
            self.assertRaisesRegex(UpReadyError, "Missing required StorageClasses"),
        ):
            check_storage_classes(ctx, ["local-path"])

    def test_check_storage_classes_skips_when_empty(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
        ) as mocked:
            check_storage_classes(ctx, [])
            mocked.assert_not_called()


class PreflightSecretsTest(unittest.TestCase):
    def test_check_secrets_passes_when_present(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        secret = SecretSpec(namespace="default", name="my-secret", key="password")
        payload = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "data": {"password": "cGFzc3dvcmQ="},
            }
        )

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(payload),
        ):
            check_secrets(ctx, [secret])

    def test_check_secrets_fails_when_missing(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        secret = SecretSpec(namespace="default", name="my-secret")

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_fail("not found"),
            ),
            self.assertRaisesRegex(UpReadyError, "Missing.*required Secret"),
        ):
            check_secrets(ctx, [secret])

    def test_check_secrets_fails_when_key_missing(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        secret = SecretSpec(namespace="default", name="my-secret", key="missing")
        payload = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "data": {"password": "cGFzc3dvcmQ="},
            }
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_ok(payload),
            ),
            self.assertRaisesRegex(UpReadyError, "Missing.*required Secret"),
        ):
            check_secrets(ctx, [secret])

    def test_check_secrets_skips_when_empty(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
        ) as mocked:
            check_secrets(ctx, [])
            mocked.assert_not_called()


class PreflightServiceAccountsTest(unittest.TestCase):
    def test_check_service_accounts_passes_when_present(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(),
        ):
            check_service_accounts(ctx, ["default/ssl-proxy"])

    def test_check_service_accounts_fails_when_missing(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_fail("not found"),
            ),
            self.assertRaisesRegex(UpReadyError, "Missing required ServiceAccount"),
        ):
            check_service_accounts(ctx, ["default/ssl-proxy"])

    def test_check_service_accounts_skips_when_empty(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
        ) as mocked:
            check_service_accounts(ctx, [])
            mocked.assert_not_called()


class PreflightCRDsTest(unittest.TestCase):
    def test_check_crds_passes_when_present(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "certificates.cert-manager.io"}},
                    {"metadata": {"name": "ingresses.networking.k8s.io"}},
                ]
            }
        )

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
            return_value=_ok(payload),
        ):
            check_crds(ctx, ["certificates.cert-manager.io"])

    def test_check_crds_fails_when_missing(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = json.dumps({"items": []})

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
                return_value=_ok(payload),
            ),
            self.assertRaisesRegex(UpReadyError, "Missing required CRD"),
        ):
            check_crds(ctx, ["certificates.cert-manager.io"])

    def test_check_crds_skips_when_empty(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.kubectl",
        ) as mocked:
            check_crds(ctx, [])
            mocked.assert_not_called()


class PreflightConflictingReleaseTest(unittest.TestCase):
    def test_check_conflicting_release_passes_when_no_release(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.helm",
            return_value=_ok("[]"),
        ):
            check_conflicting_release(ctx, True)

    def test_check_conflicting_release_fails_when_release_exists(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        releases = json.dumps([{"name": "ssl-proxy", "status": "deployed"}])

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.helm",
                return_value=_ok(releases),
            ),
            self.assertRaisesRegex(UpReadyError, "already exists"),
        ):
            check_conflicting_release(ctx, True)

    def test_migration_mode_does_not_bypass_ownership_conflict(self):
        settings = Settings()
        settings.migration_mode = "migrate"
        ctx = UpReadyContext(settings=settings)
        releases = json.dumps([{"name": "ssl-proxy", "status": "deployed"}])

        with (
            patch(
                "sslproxy_ops.commands.up_ready.preflight.shell.helm",
                return_value=_ok(releases),
            ),
            self.assertRaisesRegex(UpReadyError, "cutover plan"),
        ):
            check_conflicting_release(ctx, True)

    def test_check_conflicting_release_skips_when_disabled(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.shell.helm",
        ) as mocked:
            check_conflicting_release(ctx, False)
            mocked.assert_not_called()


class PreflightSpecLoadingTest(unittest.TestCase):
    def test_load_preflight_spec_returns_default_when_file_missing(self):
        from sslproxy_ops.commands.up_ready.preflight import _load_preflight_spec

        with patch(
            "sslproxy_ops.commands.up_ready.preflight.repo_root",
            return_value=Path("/nonexistent/ssl-proxy"),
        ):
            spec = _load_preflight_spec()
            self.assertEqual(spec.cluster.minimum_ready_nodes, 1)
            self.assertTrue(spec.conflicting_releases)


if __name__ == "__main__":
    unittest.main()
