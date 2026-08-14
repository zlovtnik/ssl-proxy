import base64
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import yaml

from sslproxy_ops import shell
from sslproxy_ops.commands.up_ready import auto_fix
from sslproxy_ops.commands.up_ready.kubernetes import (
    PREFLIGHT_REQUIRED_SECRETS,
    _generate_tidb_tls_material,
    _validate_tidb_tls_material,
    apply_secret_value,
    apply_secret_values,
    dashboard_set_file_args,
    ensure_tidb_ready,
    helm_pending_recovery_command,
    helm_release_status,
    helm_upgrade,
    kubernetes_diagnostics,
    kubernetes_up,
    node_condition_problems,
    preflight_required_secrets,
    prepare_helm_release,
    proxy_workload,
    publish_registry_images,
    recent_kubernetes_warning_lines,
    release_workloads,
    resolve_kube_context,
    rollout_restart_release_workloads,
    stackctl_preflight,
    sync_kubernetes_secrets,
    sync_tidb_secrets,
    verify_kubernetes_registry_pull,
    warn_unhealthy_nodes,
)
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError
from sslproxy_ops.config import Settings


class UpReadyKubernetesTest(unittest.TestCase):
    def test_kubernetes_and_canonical_server_are_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(Settings().deployment_target, "kubernetes")
            self.assertEqual(Settings().server_ip, "192.168.1.242")

    def test_tidb_tls_rotation_is_opt_in(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(Settings().rotate_tidb_tls)
        with patch.dict(
            os.environ,
            {"UP_READY_ROTATE_TIDB_TLS": "true"},
            clear=True,
        ):
            self.assertTrue(Settings().rotate_tidb_tls)

    def test_sensor_preflight_matches_all_node_daemonset_contract(self):
        root = Path(__file__).resolve().parents[2]
        spec = yaml.safe_load(
            (
                root
                / "ops/src/sslproxy_ops/commands/up_ready/preflight_spec.yaml"
            ).read_text()
        )
        self.assertEqual(spec["preflight"]["node_requirements"], {})

    @staticmethod
    def _tidb_tls_secret_payloads(directory: Path) -> tuple[dict, dict]:
        ca, cert, key = _generate_tidb_tls_material(
            directory,
            "ssl-proxy-tidb.default.svc.cluster.local",
        )
        return (
            {
                "metadata": {"name": "tidb-client-ca"},
                "type": "Opaque",
                "data": {"ca.crt": base64.b64encode(ca.read_bytes()).decode()},
            },
            {
                "metadata": {"name": "tidb-server-tls"},
                "type": "kubernetes.io/tls",
                "data": {
                    "tls.crt": base64.b64encode(cert.read_bytes()).decode(),
                    "tls.key": base64.b64encode(key.read_bytes()).decode(),
                },
            },
        )

    def test_sync_tidb_tls_reuses_valid_existing_pair(self):
        ctx = UpReadyContext(settings=Settings())
        with tempfile.TemporaryDirectory() as directory:
            ca_payload, tls_payload = self._tidb_tls_secret_payloads(Path(directory))
            with (
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._secret_exists",
                    return_value=True,
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._secret_payload",
                    side_effect=[ca_payload, tls_payload],
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._apply_tidb_tls_material"
                ) as apply_tls,
            ):
                self.assertTrue(sync_tidb_secrets(ctx))

        apply_tls.assert_not_called()
        self.assertEqual(len(ctx.tidb_tls_cert_checksum), 64)

    def test_tidb_tls_validation_rejects_wrong_key_and_missing_san(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            ca, cert, key = _generate_tidb_tls_material(
                Path(first),
                "ssl-proxy-tidb.default.svc.cluster.local",
            )
            _other_ca, _other_cert, other_key = _generate_tidb_tls_material(
                Path(second),
                "ssl-proxy-tidb.default.svc.cluster.local",
            )
            valid, detail = _validate_tidb_tls_material(
                ca,
                cert,
                other_key,
                ("ssl-proxy-tidb.default.svc.cluster.local",),
            )
            self.assertFalse(valid)
            self.assertIn("do not match", detail)

            valid, detail = _validate_tidb_tls_material(
                ca,
                cert,
                key,
                ("tidb.other.svc.cluster.local",),
            )
            self.assertFalse(valid)
            self.assertIn("lacks DNS SAN", detail)

    def test_tidb_tls_validation_rejects_near_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            ca, cert, key = _generate_tidb_tls_material(
                Path(directory),
                "ssl-proxy-tidb.default.svc.cluster.local",
            )
            with patch(
                "sslproxy_ops.commands.up_ready.kubernetes.TIDB_TLS_RENEWAL_SECONDS",
                20 * 365 * 24 * 60 * 60,
            ):
                valid, detail = _validate_tidb_tls_material(
                    ca,
                    cert,
                    key,
                    ("ssl-proxy-tidb.default.svc.cluster.local",),
                )
        self.assertFalse(valid)
        self.assertIn("expires within 30 days", detail)

    def test_sync_tidb_tls_forced_rotation_applies_new_pair(self):
        settings = Settings()
        settings.rotate_tidb_tls = True
        ctx = UpReadyContext(settings=settings)
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._secret_exists",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._secret_payload",
                return_value=None,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._apply_tidb_tls_material"
            ) as apply_tls,
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._statefulset_exists",
                return_value=False,
            ),
        ):
            self.assertTrue(sync_tidb_secrets(ctx))

        apply_tls.assert_called_once()
        self.assertEqual(len(ctx.tidb_tls_cert_checksum), 64)

    def test_sync_tidb_tls_restores_previous_pair_when_rollout_fails(self):
        settings = Settings()
        settings.rotate_tidb_tls = True
        ctx = UpReadyContext(settings=settings)
        with tempfile.TemporaryDirectory() as directory:
            ca_payload, tls_payload = self._tidb_tls_secret_payloads(Path(directory))
            with (
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._secret_exists",
                    return_value=True,
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._secret_payload",
                    side_effect=[ca_payload, tls_payload],
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._apply_tidb_tls_material"
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._statefulset_exists",
                    return_value=True,
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._restart_tidb_tls_consumers",
                    side_effect=[UpReadyError("rollout failed"), None],
                ),
                patch(
                    "sslproxy_ops.commands.up_ready.kubernetes._apply_secret_payload"
                ) as restore,
                self.assertRaisesRegex(UpReadyError, "previous pair was restored"),
            ):
                sync_tidb_secrets(ctx)

        self.assertEqual(restore.call_count, 2)

    def test_ensure_tidb_ready_recovers_stale_checksum(self):
        ctx = UpReadyContext(settings=Settings())
        ctx.tidb_tls_cert_checksum = "current"
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._statefulset_exists",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._tidb_statefulset_tls_checksum",
                return_value="stale",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._restart_tidb_tls_consumers"
            ) as restart,
        ):
            ensure_tidb_ready(ctx)

        restart.assert_called_once_with(ctx)
        self.assertTrue(ctx.tidb_tls_rollout_complete)

    def test_stackctl_ownership_conflict_requires_explicit_cutover(self):
        settings = Settings()
        settings.kube_context = "default"
        ctx = UpReadyContext(settings=settings)
        with (
            patch("sslproxy_ops.stack.core.load_config"),
            patch(
                "sslproxy_ops.stack.cluster.preflight",
                side_effect=RuntimeError(
                    "ownership conflicts require cutover plan: Deployment/coordinator"
                ),
            ),
            self.assertRaisesRegex(
                UpReadyError,
                r"cutover plan.*--kube-context default.*will not take ownership automatically",
            ),
        ):
            stackctl_preflight(ctx)

    def test_dashboard_files_cover_the_compose_observability_assets(self):
        args = dashboard_set_file_args()

        self.assertEqual(args.count("--set-file"), 7)
        self.assertTrue(any("stackHealthOverview=" in arg for arg in args))
        self.assertTrue(any("prometheus.alertRules=" in arg for arg in args))

    def test_postgres_secret_value_is_trimmed_and_immutable(self):
        settings = Settings()
        settings.kube_namespace = "ssl-proxy"
        ctx = UpReadyContext(settings=settings)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "postgres.key"
            source.write_text("correct-password\n")
            with patch(
                "sslproxy_ops.commands.up_ready.kubernetes._apply_rendered_resource"
            ) as mocked_apply:
                apply_secret_value(
                    ctx,
                    "postgres-credentials",
                    "password",
                    source,
                    immutable=True,
                )

        manifest = json.loads(mocked_apply.call_args.args[1])
        self.assertTrue(manifest["immutable"])
        self.assertEqual(manifest["metadata"]["namespace"], "ssl-proxy")
        self.assertEqual(
            base64.b64decode(manifest["data"]["password"]),
            b"correct-password",
        )

    def test_minio_secret_values_are_trimmed_together(self):
        settings = Settings()
        settings.kube_namespace = "ssl-proxy"
        ctx = UpReadyContext(settings=settings)

        with tempfile.TemporaryDirectory() as directory:
            access_key = Path(directory) / "minio_access_key.key"
            secret_key = Path(directory) / "minio_secret_key.key"
            access_key.write_text("access-key\n")
            secret_key.write_text("secret-key\r\n")
            with patch(
                "sslproxy_ops.commands.up_ready.kubernetes._apply_rendered_resource"
            ) as mocked_apply:
                apply_secret_values(
                    ctx,
                    "minio-credentials",
                    [
                        ("access-key", access_key),
                        ("secret-key", secret_key),
                    ],
                )

        manifest = json.loads(mocked_apply.call_args.args[1])
        self.assertFalse(manifest["immutable"])
        self.assertEqual(
            base64.b64decode(manifest["data"]["access-key"]),
            b"access-key",
        )
        self.assertEqual(
            base64.b64decode(manifest["data"]["secret-key"]),
            b"secret-key",
        )

    def test_proxy_workload_matches_chart_fullname_for_custom_releases(self):
        cases = {
            "ssl-proxy": "deployment/ssl-proxy-proxy",
            "prod": "deployment/prod-ssl-proxy-proxy",
            "prod-ssl-proxy": "deployment/prod-ssl-proxy-proxy",
        }

        for release, expected in cases.items():
            with self.subTest(release=release):
                settings = Settings()
                settings.helm_release = release
                self.assertEqual(proxy_workload(UpReadyContext(settings=settings)), expected)

    def test_empty_default_context_uses_current_kubernetes_context(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        contexts = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="docker-desktop\nserver-k8s\n", stderr=""
        )
        current = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="server-k8s\n", stderr=""
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shutil.which",
                return_value="/bin/tool",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.run",
                side_effect=[contexts, current],
            ),
        ):
            resolve_kube_context(ctx)

        self.assertEqual(ctx.settings.kube_context, "server-k8s")

    def test_missing_configured_context_is_rejected(self):
        settings = Settings()
        settings.kube_context = "missing"
        ctx = UpReadyContext(settings=settings)
        contexts = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="server-k8s\n", stderr=""
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shutil.which",
                return_value="/bin/tool",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.run",
                return_value=contexts,
            ),
            self.assertRaises(UpReadyError),
        ):
            resolve_kube_context(ctx)

    def test_helm_upgrade_uses_registry_rollout_revision_and_waits_for_jobs(self):
        settings = Settings()
        settings.server_ip = "192.168.1.242"
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.242:32000/"
        settings.image_tag = "latest"
        settings.schema_migrator_public_hostname = "schema.example.com"
        settings.acme_email = "ops@example.com"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings, run_ts="2026-07-14T12:00:00-0400")
        environment = {
            "REGISTRY": "192.168.1.242:32000/",
            "IMAGE_TAG": "latest",
            "WG_PEERS": "peer1,peer2",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        deployed = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "kind": "Deployment",
                            "metadata": {"generation": 1},
                            "spec": {"replicas": 1},
                            "status": {"observedGeneration": 1, "readyReplicas": 1},
                        }
                    ]
                }
            ),
            stderr="",
        )
        upgraded = subprocess.CompletedProcess(args=["helm"], returncode=0, stdout="", stderr="")
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, upgraded],
            ) as mocked_helm,
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                return_value=deployed,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.preflight_required_secrets",
            ),
        ):
            helm_upgrade(ctx)

        dependency_args = mocked_helm.call_args_list[0].args
        args = mocked_helm.call_args_list[-1].args
        self.assertEqual(dependency_args[:2], ("dependency", "update"))
        self.assertEqual(args[0], "upgrade")
        self.assertNotIn("--install", args)
        self.assertIn("global.image.registry=192.168.1.242:32000", args)
        self.assertIn("global.rolloutRevision=2026-07-14T12:00:00-0400", args)
        self.assertIn("proxy.wireguard.peerNames=peer1,peer2", args)
        self.assertIn("schemaMigrator.backend.image.tag=latest", args)
        self.assertIn("schemaMigrator.ui.image.tag=latest", args)
        self.assertIn("schemaMigrator.ui.browserOrigin=http://192.168.1.242:8081", args)
        self.assertIn("schemaMigrator.publicHostname=schema.example.com", args)
        self.assertIn("schemaMigrator.traefik.acme.email=ops@example.com", args)
        self.assertIn("schemaMigrator.keycloak.browserOrigin=http://192.168.1.242:8180", args)
        self.assertIn("schemaMigrator.keycloak.adminHostname=http://192.168.1.242:8180", args)
        self.assertIn(
            "global.shared.keycloak.issuer=http://192.168.1.242:8180/realms/middleware",
            args,
        )
        self.assertIn("atherosSearch.ui.image.tag=latest", args)
        self.assertIn("atherosSearch.embeddingBackend=http://192.168.1.242:8083", args)
        self.assertEqual(args.count("--set-literal"), 17)
        self.assertEqual(args.count("--set"), 3)
        self.assertIn("proxy.wireguard.obfuscation.enabled=true", args)
        self.assertNotIn("--set-string", args)
        self.assertIn("--server-side=true", args)
        self.assertIn("--wait=watcher", args)
        self.assertIn("--wait-for-jobs", args)
        self.assertEqual(args[args.index("--timeout") + 1], "30m")
        self.assertIn("--history-max", args)
        self.assertIn("--rollback-on-failure", args)
        self.assertEqual(mocked_helm.call_args_list[-1].kwargs["context"], "server-k8s")
        self.assertTrue(mocked_helm.call_args_list[-1].kwargs["stream"])

    def test_helm_upgrade_requires_validated_settings(self):
        settings = Settings()
        settings.registry = None
        settings.image_tag = None

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.preflight_required_secrets",
            ),
            self.assertRaisesRegex(UpReadyError, "REGISTRY"),
        ):
            helm_upgrade(UpReadyContext(settings=settings))

    def test_helm_first_install_does_not_request_rollback(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.242:5000"
        settings.image_tag = "latest"
        settings.schema_migrator_public_hostname = "schema.example.com"
        settings.acme_email = "ops@example.com"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings)
        environment = {
            "REGISTRY": "192.168.1.242:5000",
            "IMAGE_TAG": "latest",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        missing = subprocess.CompletedProcess(
            args=["helm"], returncode=1, stdout="", stderr="release not found"
        )
        installed = subprocess.CompletedProcess(args=["helm"], returncode=0, stdout="", stderr="")
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, missing, installed],
            ) as mocked_helm,
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.preflight_required_secrets",
            ),
        ):
            helm_upgrade(ctx)

        args = mocked_helm.call_args_list[-1].args
        self.assertEqual(args[0], "install")
        self.assertNotIn("--install", args)
        self.assertNotIn("--history-max", args)
        self.assertNotIn("--rollback-on-failure", args)

    def test_helm_fresh_install_uses_install(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.242:5000"
        settings.image_tag = "latest"
        settings.schema_migrator_public_hostname = "schema.example.com"
        settings.acme_email = "ops@example.com"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings)
        environment = {
            "REGISTRY": "192.168.1.242:5000",
            "IMAGE_TAG": "latest",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        install_result = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        no_resources = subprocess.CompletedProcess(
            args=["kubectl"], returncode=1, stdout="", stderr="not found"
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, install_result],
            ) as mocked_helm,
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=[no_resources, no_resources],
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.preflight_required_secrets",
            ),
        ):
            helm_upgrade(ctx)

        install = mocked_helm.call_args_list[-1].args
        self.assertEqual(install[0], "install")
        self.assertNotIn("--install", install)

    def test_preflight_required_secrets_raises_on_missing(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        ctx = UpReadyContext(settings=settings)
        present_stdout = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "data": {
                    "password": "cGFzc3dvcmQ=",
                    "ca.crt": "Y2EuY3J0",
                    "dsn": "ZHNu",
                },
            }
        )
        present = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout=present_stdout, stderr=""
        )
        missing = subprocess.CompletedProcess(
            args=["kubectl"], returncode=1, stdout="", stderr="not found"
        )
        side_effects = []
        for name in PREFLIGHT_REQUIRED_SECRETS:
            side_effects.append(present if name != "tidb-client-ca" else missing)

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=side_effects,
            ) as mocked,
            self.assertRaisesRegex(UpReadyError, "tidb-client-ca"),
        ):
            preflight_required_secrets(ctx)

        expected_calls = len(PREFLIGHT_REQUIRED_SECRETS)
        self.assertEqual(len(mocked.call_args_list), expected_calls)

    def test_preflight_required_secrets_passes_when_all_present(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        ctx = UpReadyContext(settings=settings)
        present_stdout = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "data": {
                    "password": "cGFzc3dvcmQ=",
                    "ca.crt": "Y2EuY3J0",
                    "dsn": "ZHNu",
                },
            }
        )
        present = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout=present_stdout, stderr=""
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=present,
        ):
            preflight_required_secrets(ctx)  # should not raise

    def test_preflight_required_secrets_constant_covers_all_chart_references(self):
        expected = {
            "redis-runtime",
            "tidb-client-ca",
            "tidb-octopus",
            "tidb-atheros-search",
            "tidb-schema-migrator",
            "tidb-keycloak",
            "tidb-schema-owner",
        }
        self.assertEqual(set(PREFLIGHT_REQUIRED_SECRETS.keys()), expected)

    def test_helm_release_status_rejects_malformed_json(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        malformed = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="not-json", stderr=""
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=malformed,
        ):
            result = helm_release_status(ctx)
            self.assertIsNone(result)

    def test_progress_deadline_exceeded_is_degraded_not_release_failed(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        degraded = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "kind": "Deployment",
                            "metadata": {"name": "api", "generation": 2},
                            "status": {
                                "observedGeneration": 2,
                                "conditions": [
                                    {
                                        "type": "Progressing",
                                        "status": "False",
                                        "reason": "ProgressDeadlineExceeded",
                                    }
                                ],
                            },
                        }
                    ]
                }
            ),
            stderr="",
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=degraded,
        ):
            self.assertEqual(helm_release_status(ctx), "degraded")

    def test_helm_release_status_checks_statefulsets_and_daemonsets(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        resources = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "kind": "StatefulSet",
                            "metadata": {"generation": 3},
                            "spec": {"replicas": 2},
                            "status": {"observedGeneration": 3, "readyReplicas": 2},
                        },
                        {
                            "kind": "DaemonSet",
                            "metadata": {"generation": 4},
                            "status": {
                                "observedGeneration": 4,
                                "desiredNumberScheduled": 2,
                                "numberReady": 1,
                            },
                        },
                    ]
                }
            ),
            stderr="",
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=resources,
        ):
            self.assertEqual(helm_release_status(ctx), "degraded")

    def test_degraded_release_replaces_only_stalled_workloads_without_helm_uninstall(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        removed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.helm_release_status",
                return_value="degraded",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._find_failed_workloads",
                return_value=["deploy/api"],
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=[removed, removed],
            ) as mock_kubectl,
            patch("sslproxy_ops.commands.up_ready.kubernetes.shell.helm") as mock_helm,
        ):
            self.assertTrue(prepare_helm_release(ctx))

        self.assertIn("--cascade=foreground", mock_kubectl.call_args_list[0].args)
        mock_helm.assert_not_called()

    def test_degraded_release_fails_when_stalled_workload_does_not_disappear(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        removed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        present = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="deployment.apps/api\n", stderr=""
        )
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.helm_release_status",
                return_value="degraded",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._find_failed_workloads",
                return_value=["deploy/api"],
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=[removed, *([present] * 30)],
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.time.sleep"),
            self.assertRaisesRegex(UpReadyError, "deploy/api.*deleted"),
        ):
            prepare_helm_release(ctx)

    def test_degraded_release_fails_when_no_stalled_workload_is_resolved(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.helm_release_status",
                return_value="degraded",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._find_failed_workloads",
                return_value=[],
            ),
            self.assertRaisesRegex(UpReadyError, "no failed workloads"),
        ):
            prepare_helm_release(ctx)

    def test_pending_rollback_reports_latest_stable_revision(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        ctx = UpReadyContext(settings=settings)
        deployed_resources = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps({
                "items": [{
                    "kind": "Deployment",
                    "metadata": {"name": "proxy", "generation": 1},
                    "spec": {"replicas": 1},
                    "status": {"observedGeneration": 1, "readyReplicas": 1, "conditions": []},
                }]
            }),
            stderr="",
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=deployed_resources,
        ):
            self.assertTrue(prepare_helm_release(ctx))

    def test_pending_recovery_uses_canonical_helm_upgrade_configuration(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        settings.registry = "registry.example.test"
        settings.image_tag = "reviewed"
        settings.schema_migrator_public_hostname = "schema.example.test"
        settings.acme_email = "ops@example.test"
        ctx = UpReadyContext(settings=settings)
        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.dashboard_set_file_args",
            return_value=[],
        ):
            command = helm_pending_recovery_command(ctx)

        self.assertTrue(command.startswith("helm --kube-context server-k8s upgrade ssl-proxy "))
        self.assertIn("--namespace default", command)
        self.assertIn("--server-side=true", command)
        self.assertIn("--rollback-on-failure", command)

    def test_recent_kubernetes_warnings_ignore_events_before_run(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings, run_ts="2026-07-18T16:00:00-04:00")
        events = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "lastTimestamp": "2026-07-18T19:59:59Z",
                            "reason": "OldWarning",
                            "message": "historical failure",
                            "involvedObject": {"kind": "Pod", "name": "old"},
                        },
                        {
                            "lastTimestamp": "2026-07-18T20:00:01Z",
                            "reason": "FailedCreatePodSandBox",
                            "message": "flannel could not load subnet.env",
                            "involvedObject": {"kind": "Pod", "name": "current"},
                        },
                    ]
                }
            ),
            stderr="",
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=events,
        ):
            lines = recent_kubernetes_warning_lines(ctx)

        self.assertEqual(len(lines), 1)
        self.assertIn("Pod/current", lines[0])
        self.assertNotIn("historical failure", lines[0])

    def test_kubernetes_diagnostics_prints_root_cause_before_bulk_output(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        ctx.classify("Helm release ssl-proxy remains pending-rollback")
        empty_events = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout='{"items":[]}', stderr=""
        )
        completed = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="", stderr=""
        )
        missing = subprocess.CompletedProcess(
            args=["kubectl"], returncode=1, stdout="", stderr="not found"
        )
        deployed_resources = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps({
                "items": [{
                    "kind": "Deployment",
                    "metadata": {"name": "proxy", "generation": 1},
                    "spec": {"replicas": 1},
                    "status": {"observedGeneration": 1, "readyReplicas": 1, "conditions": []},
                }]
            }),
            stderr="",
        )
        def kubectl_side_effect(*args, **_kwargs):
            if "events" in args:
                return empty_events
            if "pods" in args:
                print("BULK POD OUTPUT")
                return completed
            if "deploy,sts,ds" in args:
                return deployed_resources
            return missing

        output = StringIO()
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                return_value=subprocess.CompletedProcess(
                    args=["helm"],
                    returncode=0,
                    stdout='{"info":{"status":"pending-rollback"}}',
                    stderr="",
                ),
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=kubectl_side_effect,
            ),
            redirect_stdout(output),
        ):
            kubernetes_diagnostics(ctx)

        rendered = output.getvalue()
        self.assertIn("helm_release_status=deployed", rendered)
        self.assertLess(
            rendered.index("class=helm_pending_operation"),
            rendered.index("BULK POD OUTPUT"),
        )

    def test_kubernetes_diagnostics_classifies_current_cni_event(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings, run_ts="2026-07-18T16:00:00-04:00")
        ctx.classify("helm upgrade failed: context canceled")
        events = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "lastTimestamp": "2026-07-18T20:00:01Z",
                            "reason": "FailedCreatePodSandBox",
                            "message": "flannel failed to load /run/flannel/subnet.env",
                            "involvedObject": {"kind": "Pod", "name": "proxy"},
                        }
                    ]
                }
            ),
            stderr="",
        )
        completed = subprocess.CompletedProcess(args=["tool"], returncode=0, stdout="", stderr="")
        missing = subprocess.CompletedProcess(
            args=["kubectl"], returncode=1, stdout="", stderr="not found"
        )

        def kubectl_side_effect(*args, **_kwargs):
            if "events" in args:
                return events
            if "pods" in args:
                return completed
            return missing

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                return_value=subprocess.CompletedProcess(
                    args=["helm"],
                    returncode=0,
                    stdout='{"info":{"status":"failed"}}',
                    stderr="",
                ),
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=kubectl_side_effect,
            ),
            redirect_stdout(StringIO()),
        ):
            kubernetes_diagnostics(ctx)

        self.assertEqual(ctx.last_failure.name, "kubernetes_cni_unavailable")

    def test_registry_pull_probe_uses_canonical_registry_and_cleans_up(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        ctx = UpReadyContext(settings=settings)
        environment = {"REGISTRY": "192.168.1.242:5000"}
        completed = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="", stderr=""
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._apply_rendered_resource"
            ) as mocked_apply,
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                return_value=completed,
            ) as mocked_kubectl,
        ):
            verify_kubernetes_registry_pull(ctx)

        manifest = json.loads(mocked_apply.call_args.args[1])
        self.assertEqual(
            manifest["spec"]["containers"][0]["image"],
            "192.168.1.242:5000/busybox:1.37.0",
        )
        self.assertEqual(mocked_kubectl.call_count, 3)

    def test_schema_migrator_secret_groups_are_synchronized(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with (
            patch("sslproxy_ops.commands.up_ready.kubernetes.ensure_namespace"),
            patch("sslproxy_ops.commands.up_ready.kubernetes.apply_secret_value"),
            patch("sslproxy_ops.commands.up_ready.kubernetes.apply_secret_values") as values,
            patch("sslproxy_ops.commands.up_ready.kubernetes.apply_secret"),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.peer_names",
                return_value=[],
            ),
        ):
            sync_kubernetes_secrets(ctx)

        groups = {
            call.args[1]: [key for key, _path in call.args[2]] for call in values.call_args_list
        }
        self.assertEqual(
            groups["schema-migrator-backend"],
            ["encrypt-key", "jwt-secret", "api-bearer-token"],
        )
        self.assertEqual(groups["schema-migrator-state-db"], ["password"])
        self.assertEqual(
            groups["schema-migrator-keycloak"],
            ["database-password", "bootstrap-admin-password"],
        )
        self.assertEqual(
            groups["schema-migrator-bootstrap"],
            ["application-admin-password"],
        )

    def test_schema_migrator_image_pipeline_is_complete_and_pinned(self):
        root = Path(__file__).resolve().parents[2]
        makefile = (root / "Makefile").read_text()
        chart_values = yaml.safe_load(
            (root / "helm/ssl-proxy/charts/schema-migrator/values.yaml").read_text()
        )

        for image in ("schema-migrator-backend", "schema-migrator-ui"):
            self.assertIn(image, makefile)

        pinned_images = {
            "quay.io/keycloak/keycloak:26.2.5",
            "traefik:v3.6.2",
            "busybox:1.37.0",
        }
        for image in pinned_images:
            self.assertNotIn(image, makefile)

        self.assertNotIn("bootstrapImage", chart_values["stateStore"])
        self.assertEqual(
            f"{chart_values['keycloak']['image']['repository']}:"
            f"{chart_values['keycloak']['image']['tag']}",
            "quay.io/keycloak/keycloak:26.2.5",
        )
        self.assertEqual(
            f"{chart_values['traefik']['image']['repository']}:"
            f"{chart_values['traefik']['image']['tag']}",
            "traefik:v3.6.2",
        )

    def test_registry_publish_builds_first_party_images(self):
        settings = Settings()
        settings.registry = "192.168.1.242:32000/"
        settings.image_tag = "latest"
        settings.mirror_registry_images = False
        ctx = UpReadyContext(settings=settings)

        with patch("sslproxy_ops.commands.up_ready.kubernetes.shell.run") as mocked_run:
            publish_registry_images(ctx)

        self.assertEqual(
            [call.args[0][1] for call in mocked_run.call_args_list],
            ["publish-all"],
        )
        self.assertIn("REGISTRY=192.168.1.242:32000", mocked_run.call_args_list[0].args[0])
        self.assertIn("ATHEROS_SEARCH_UI_API_BASE=", mocked_run.call_args_list[0].args[0])

    def test_registry_publish_requires_validated_settings(self):
        settings = Settings()
        settings.registry = None
        ctx = UpReadyContext(settings=settings)

        with self.assertRaisesRegex(UpReadyError, "REGISTRY"):
            publish_registry_images(ctx)

    def test_registry_publish_does_not_require_environment_when_disabled(self):
        settings = Settings()
        settings.build_registry_images = False
        settings.mirror_registry_images = False
        ctx = UpReadyContext(settings=settings)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sslproxy_ops.commands.up_ready.kubernetes.shell.run") as mocked_run,
        ):
            publish_registry_images(ctx)

        mocked_run.assert_not_called()

    def test_kubernetes_auto_fix_marks_successful_repairs(self):
        settings = Settings()
        settings.deployment_target = "kubernetes"
        settings.profile_mode = "iphone"
        ctx = UpReadyContext(settings=settings)

        with (
            patch("sslproxy_ops.commands.up_ready.apply_profile_runtime_env") as mocked_profile,
            patch("sslproxy_ops.commands.up_ready.helm_upgrade") as mocked_upgrade,
        ):
            self.assertTrue(auto_fix(ctx, "profile_obfuscation_mismatch"))

        mocked_profile.assert_called_once_with(ctx)
        mocked_upgrade.assert_called_once_with(ctx)
        self.assertIn("profile_obfuscation_mismatch", ctx.auto_fixed_classes)

    def test_kubernetes_auto_fix_does_not_mark_failed_repairs(self):
        settings = Settings()
        settings.deployment_target = "kubernetes"
        settings.profile_mode = "iphone"
        ctx = UpReadyContext(settings=settings)

        with (
            patch("sslproxy_ops.commands.up_ready.apply_profile_runtime_env"),
            patch(
                "sslproxy_ops.commands.up_ready.helm_upgrade",
                side_effect=UpReadyError("upgrade failed"),
            ),
        ):
            self.assertFalse(auto_fix(ctx, "profile_obfuscation_mismatch"))

        self.assertNotIn("profile_obfuscation_mismatch", ctx.auto_fixed_classes)

    def test_kubernetes_auto_fix_checks_secret_sync_result(self):
        settings = Settings()
        settings.deployment_target = "kubernetes"
        ctx = UpReadyContext(settings=settings)

        with (
            patch("sslproxy_ops.commands.up_ready.ensure_local_peer_material"),
            patch("sslproxy_ops.commands.up_ready.sync_kubernetes_secrets", return_value=False),
            patch("sslproxy_ops.commands.up_ready.helm_upgrade") as mocked_upgrade,
        ):
            self.assertFalse(auto_fix(ctx, "wg_peer_material_missing"))

        mocked_upgrade.assert_not_called()
        self.assertNotIn("wg_peer_material_missing", ctx.auto_fixed_classes)

    def test_node_condition_problems_reports_unhealthy_states(self):
        node = {
            "metadata": {"name": "node-1"},
            "spec": {"unschedulable": True},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "False"},
                    {"type": "MemoryPressure", "status": "True"},
                    {"type": "DiskPressure", "status": "False"},
                    {"type": "PIDPressure", "status": "True"},
                    {"type": "NetworkUnavailable", "status": "True"},
                ]
            },
        }

        self.assertEqual(
            node_condition_problems(node),
            [
                "node-1: Ready=False",
                "node-1: MemoryPressure=True",
                "node-1: PIDPressure=True",
                "node-1: NetworkUnavailable=True",
                "node-1: unschedulable (cordoned)",
            ],
        )

    def test_node_condition_problems_empty_for_ready_node(self):
        node = {
            "metadata": {"name": "node-1"},
            "spec": {},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "MemoryPressure", "status": "False"},
                    {"type": "DiskPressure", "status": "False"},
                    {"type": "PIDPressure", "status": "False"},
                    {"type": "NetworkUnavailable", "status": "False"},
                ]
            },
        }

        self.assertEqual(node_condition_problems(node), [])

    def test_warn_unhealthy_nodes_never_blocks_on_kubectl_failure(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        failed = subprocess.CompletedProcess(
            args=["kubectl"], returncode=1, stdout="", stderr="connection refused"
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                return_value=failed,
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.warn") as mocked_warn,
        ):
            warn_unhealthy_nodes(ctx)

        mocked_warn.assert_called_once()
        self.assertIn("connection refused", mocked_warn.call_args.args[0])

    def test_warn_unhealthy_nodes_reports_problem_nodes(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        payload = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout=json.dumps(
                {
                    "items": [
                        {
                            "metadata": {"name": "node-bad"},
                            "spec": {},
                            "status": {"conditions": [{"type": "Ready", "status": "False"}]},
                        }
                    ]
                }
            ),
            stderr="",
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                return_value=payload,
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.warn") as mocked_warn,
        ):
            warn_unhealthy_nodes(ctx)

        mocked_warn.assert_called_once_with("node health: node-bad: Ready=False")

    def test_release_workloads_selects_deployments_and_daemonsets(self):
        settings = Settings()
        settings.kube_namespace = "ssl-proxy"
        settings.kube_context = "server-k8s"
        settings.helm_release = "ssl-proxy"
        ctx = UpReadyContext(settings=settings)
        listed = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout="deployment.apps/ssl-proxy-proxy\ndaemonset.apps/ssl-proxy-atheros-sensor\n",
            stderr="",
        )

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            return_value=listed,
        ) as mocked_kubectl:
            workloads = release_workloads(ctx)

        self.assertEqual(
            workloads,
            ["deployment.apps/ssl-proxy-proxy", "daemonset.apps/ssl-proxy-atheros-sensor"],
        )
        args = mocked_kubectl.call_args.args
        self.assertIn("deployments,daemonsets", args)
        self.assertIn("app.kubernetes.io/instance=ssl-proxy", args)

    def test_rollout_restart_restarts_and_verifies_each_workload(self):
        settings = Settings()
        settings.kube_namespace = "ssl-proxy"
        settings.kube_context = "server-k8s"
        settings.helm_release = "ssl-proxy"
        settings.rollout_status_timeout = "7m"
        ctx = UpReadyContext(settings=settings)
        listed = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout="deployment.apps/ssl-proxy-proxy\ndaemonset.apps/ssl-proxy-atheros-sensor\n",
            stderr="",
        )
        ok = subprocess.CompletedProcess(args=["kubectl"], returncode=0, stdout="", stderr="")

        with patch(
            "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
            side_effect=[listed, ok, ok, ok],
        ) as mocked_kubectl:
            rollout_restart_release_workloads(ctx)

        restart = mocked_kubectl.call_args_list[1].args
        self.assertEqual(restart[:4], ("--namespace", "ssl-proxy", "rollout", "restart"))
        self.assertIn("deployment.apps/ssl-proxy-proxy", restart)
        self.assertIn("daemonset.apps/ssl-proxy-atheros-sensor", restart)
        statuses = [call.args for call in mocked_kubectl.call_args_list[2:]]
        self.assertEqual(len(statuses), 2)
        for status_args, workload in zip(
            statuses,
            ["deployment.apps/ssl-proxy-proxy", "daemonset.apps/ssl-proxy-atheros-sensor"],
            strict=True,
        ):
            self.assertEqual(status_args[2:4], ("rollout", "status"))
            self.assertIn(workload, status_args)
            self.assertIn("--timeout=7m", status_args)

    def test_rollout_restart_raises_when_status_fails(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        listed = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout="deployment.apps/ssl-proxy-proxy\n",
            stderr="",
        )
        ok = subprocess.CompletedProcess(args=["kubectl"], returncode=0, stdout="", stderr="")

        def kubectl_side_effect(*args, **kwargs):
            if "status" in args:
                raise shell.ShellCommandError(
                    command=tuple(args),
                    cwd=Path("."),
                    returncode=1,
                    stdout="",
                    stderr="timed out waiting for the condition",
                )
            if "restart" in args:
                return ok
            return listed

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.kubectl",
                side_effect=kubectl_side_effect,
            ),
            self.assertRaises(shell.ShellCommandError),
        ):
            rollout_restart_release_workloads(ctx)

    def test_kubernetes_up_returns_false_when_rollout_restart_fails(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.sync_kubernetes_secrets",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.sync_tidb_secrets",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._statefulset_exists",
                return_value=False,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.ensure_tidb_ready",
                return_value=None,
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.publish_registry_images"),
            patch("sslproxy_ops.commands.up_ready.kubernetes.verify_kubernetes_registry_pull"),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.helm_upgrade",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.rollout_restart_release_workloads",
                side_effect=UpReadyError("rollout status timed out"),
            ),
        ):
            self.assertFalse(kubernetes_up(ctx))

        self.assertIn("rollout status timed out", ctx.last_failure_text)

    def test_existing_split_preflight_runs_before_tidb_tls_sync(self):
        settings = Settings()
        settings.stack_mode = "split"
        ctx = UpReadyContext(settings=settings)
        calls: list[str] = []
        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.sync_kubernetes_secrets",
                side_effect=lambda _ctx: calls.append("secrets"),
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes._statefulset_exists",
                return_value=True,
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.stackctl_preflight",
                side_effect=lambda _ctx: calls.append("preflight"),
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.sync_tidb_secrets",
                side_effect=lambda _ctx: calls.append("tidb_tls"),
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.ensure_tidb_ready"),
            patch("sslproxy_ops.commands.up_ready.kubernetes.publish_registry_images"),
            patch("sslproxy_ops.commands.up_ready.kubernetes.verify_kubernetes_registry_pull"),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.deploy_kubernetes_release",
                return_value=True,
            ),
            patch("sslproxy_ops.commands.up_ready.kubernetes.rollout_restart_release_workloads"),
        ):
            self.assertTrue(kubernetes_up(ctx))

        self.assertLess(calls.index("preflight"), calls.index("tidb_tls"))


if __name__ == "__main__":
    unittest.main()
