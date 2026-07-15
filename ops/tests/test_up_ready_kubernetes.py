import json
import os
import subprocess
import unittest
from unittest.mock import patch

from sslproxy_ops.commands.up_ready import auto_fix
from sslproxy_ops.commands.up_ready.kubernetes import (
    dashboard_set_file_args,
    helm_upgrade,
    helm_release_status,
    proxy_workload,
    publish_registry_images,
    resolve_kube_context,
    verify_kubernetes_registry_pull,
)
from sslproxy_ops.commands.up_ready.model import UpReadyContext, UpReadyError
from sslproxy_ops.config import Settings


class UpReadyKubernetesTest(unittest.TestCase):
    def test_kubernetes_is_the_default_deployment_target(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(Settings().deployment_target, "kubernetes")

    def test_dashboard_files_cover_the_compose_observability_assets(self):
        args = dashboard_set_file_args()

        self.assertEqual(args.count("--set-file"), 8)
        self.assertTrue(any("stackHealthOverview=" in arg for arg in args))
        self.assertTrue(any("prometheus.alertRules=" in arg for arg in args))
        self.assertTrue(any("postgresExporter.queries=" in arg for arg in args))

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
            patch("sslproxy_ops.commands.up_ready.kubernetes.shutil.which", return_value="/bin/tool"),
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
        settings.server_ip = "192.168.1.221"
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.221:32000/"
        settings.image_tag = "latest"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings, run_ts="2026-07-14T12:00:00-0400")
        environment = {
            "REGISTRY": "192.168.1.221:32000/",
            "IMAGE_TAG": "latest",
            "WG_PEERS": "peer1,peer2",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        deployed = subprocess.CompletedProcess(
            args=["helm"],
            returncode=0,
            stdout='{"info":{"status":"deployed"}}',
            stderr="",
        )
        upgraded = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, deployed, upgraded],
            ) as mocked_helm,
        ):
            helm_upgrade(ctx)

        dependency_args = mocked_helm.call_args_list[0].args
        args = mocked_helm.call_args_list[-1].args
        self.assertEqual(dependency_args[:2], ("dependency", "update"))
        self.assertEqual(args[0], "upgrade")
        self.assertNotIn("--install", args)
        self.assertIn("global.image.registry=192.168.1.221:32000", args)
        self.assertIn("global.rolloutRevision=2026-07-14T12:00:00-0400", args)
        self.assertIn("proxy.wireguard.peerNames=peer1,peer2", args)
        self.assertEqual(args.count("--set-literal"), 10)
        self.assertEqual(args.count("--set"), 3)
        self.assertIn("proxy.wireguard.obfuscation.enabled=true", args)
        self.assertNotIn("--set-string", args)
        self.assertIn("--server-side=true", args)
        self.assertIn("--wait=watcher", args)
        self.assertIn("--wait-for-jobs", args)
        self.assertIn("--history-max", args)
        self.assertIn("--rollback-on-failure", args)
        self.assertEqual(mocked_helm.call_args_list[-1].kwargs["context"], "server-k8s")
        self.assertTrue(mocked_helm.call_args_list[-1].kwargs["capture"])

    def test_helm_upgrade_requires_validated_settings(self):
        settings = Settings()
        settings.registry = None
        settings.image_tag = None

        with self.assertRaisesRegex(UpReadyError, "REGISTRY"):
            helm_upgrade(UpReadyContext(settings=settings))

    def test_helm_first_install_does_not_request_rollback(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.221:5000"
        settings.image_tag = "latest"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings)
        environment = {
            "REGISTRY": "192.168.1.221:5000",
            "IMAGE_TAG": "latest",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        missing = subprocess.CompletedProcess(
            args=["helm"], returncode=1, stdout="", stderr="release not found"
        )
        installed = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, missing, installed],
            ) as mocked_helm,
        ):
            helm_upgrade(ctx)

        args = mocked_helm.call_args_list[-1].args
        self.assertEqual(args[0], "install")
        self.assertNotIn("--install", args)
        self.assertNotIn("--history-max", args)
        self.assertNotIn("--rollback-on-failure", args)

    def test_helm_stale_first_install_is_removed_before_retry(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        settings.registry = "192.168.1.221:5000"
        settings.image_tag = "latest"
        settings.wg_port = 51820
        settings.wg_internal_port = 443
        settings.wg_obfuscation_enabled = True
        ctx = UpReadyContext(settings=settings)
        environment = {
            "REGISTRY": "192.168.1.221:5000",
            "IMAGE_TAG": "latest",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }
        uninstalling = subprocess.CompletedProcess(
            args=["helm"],
            returncode=0,
            stdout='{"info":{"status":"uninstalling"}}',
            stderr="",
        )
        completed = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        dependencies_updated = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="", stderr=""
        )
        missing = subprocess.CompletedProcess(
            args=["helm"], returncode=1, stdout="", stderr="release not found"
        )

        with (
            patch.dict(os.environ, environment, clear=False),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                side_effect=[dependencies_updated, uninstalling, completed, missing, completed],
            ) as mocked_helm,
        ):
            helm_upgrade(ctx)

        cleanup = mocked_helm.call_args_list[2].args
        install = mocked_helm.call_args_list[4].args
        self.assertEqual(cleanup[0], "uninstall")
        self.assertIn("--no-hooks", cleanup)
        self.assertEqual(install[0], "install")

    def test_helm_release_status_rejects_malformed_json(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        malformed = subprocess.CompletedProcess(
            args=["helm"], returncode=0, stdout="not-json", stderr=""
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.helm",
                return_value=malformed,
            ),
            self.assertRaisesRegex(UpReadyError, "parse Helm release status"),
        ):
            helm_release_status(ctx)

    def test_registry_pull_probe_uses_canonical_registry_and_cleans_up(self):
        settings = Settings()
        settings.kube_context = "server-k8s"
        ctx = UpReadyContext(settings=settings)
        environment = {"REGISTRY": "192.168.1.221:5000"}
        completed = subprocess.CompletedProcess(args=["kubectl"], returncode=0, stdout="", stderr="")

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
            "192.168.1.221:5000/redis:7-alpine",
        )
        self.assertEqual(mocked_kubectl.call_count, 3)

    def test_registry_publish_builds_and_mirrors(self):
        settings = Settings()
        settings.registry = "192.168.1.221:32000/"
        settings.image_tag = "latest"
        ctx = UpReadyContext(settings=settings)

        with patch("sslproxy_ops.commands.up_ready.kubernetes.shell.run") as mocked_run:
            publish_registry_images(ctx)

        self.assertEqual(
            [call.args[0][1] for call in mocked_run.call_args_list],
            ["registry-build-all", "registry-mirror-all"],
        )
        self.assertIn("REGISTRY=192.168.1.221:32000", mocked_run.call_args_list[0].args[0])
        self.assertIn("REGISTRY=192.168.1.221:32000", mocked_run.call_args_list[1].args[0])

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
            patch(
                "sslproxy_ops.commands.up_ready.apply_profile_runtime_env"
            ) as mocked_profile,
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


if __name__ == "__main__":
    unittest.main()
