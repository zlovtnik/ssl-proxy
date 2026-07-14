import os
import subprocess
import unittest
from unittest.mock import patch

from sslproxy_ops.commands.up_ready.kubernetes import (
    dashboard_set_file_args,
    helm_upgrade,
    publish_registry_images,
    resolve_kube_context,
)
from sslproxy_ops.commands.up_ready.model import UpReadyContext
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

    def test_missing_default_context_uses_the_only_microk8s_context(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        completed = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=0,
            stdout="docker-desktop\nmicrok8s\n",
            stderr="",
        )

        with patch("sslproxy_ops.commands.up_ready.kubernetes.shell.run", return_value=completed):
            resolve_kube_context(ctx)

        self.assertEqual(ctx.settings.kube_context, "microk8s")

    def test_server_install_uses_local_microk8s_without_a_context(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        no_contexts = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="", stderr=""
        )
        ready = subprocess.CompletedProcess(
            args=["microk8s"], returncode=0, stdout="microk8s is running", stderr=""
        )

        with (
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shutil.which",
                return_value="/snap/bin/tool",
            ),
            patch(
                "sslproxy_ops.commands.up_ready.kubernetes.shell.run",
                side_effect=[no_contexts, ready],
            ),
        ):
            resolve_kube_context(ctx)

        self.assertEqual(ctx.settings.kube_context, "")

    def test_helm_upgrade_uses_registry_rollout_revision_and_waits_for_jobs(self):
        settings = Settings()
        settings.server_ip = "192.168.1.221"
        ctx = UpReadyContext(settings=settings, run_ts="2026-07-14T12:00:00-0400")
        environment = {
            "REGISTRY": "192.168.1.221:32000/",
            "IMAGE_TAG": "latest",
            "WG_PEERS": "peer1,peer2",
            "WG_PORT": "51820",
            "WG_INTERNAL_PORT": "443",
            "WG_OBFUSCATION_ENABLED": "true",
        }

        with (
            patch.dict(os.environ, environment, clear=False),
            patch("sslproxy_ops.commands.up_ready.kubernetes.shell.helm") as mocked_helm,
        ):
            helm_upgrade(ctx)

        args = mocked_helm.call_args.args
        self.assertIn("global.image.registry=192.168.1.221:32000", args)
        self.assertIn("global.rolloutRevision=2026-07-14T12:00:00-0400", args)
        self.assertIn("proxy.adminService.externalIPs[0]=192.168.1.221", args)
        self.assertIn("observability.prometheus.service.externalIPs[0]=192.168.1.221", args)
        self.assertIn("--wait-for-jobs", args)
        self.assertEqual(mocked_helm.call_args.kwargs["context"], "microk8s-ssl-proxy")

    def test_registry_publish_builds_and_mirrors(self):
        settings = Settings()
        ctx = UpReadyContext(settings=settings)
        environment = {"REGISTRY": "192.168.1.221:32000", "IMAGE_TAG": "latest"}

        with (
            patch.dict(os.environ, environment, clear=False),
            patch("sslproxy_ops.commands.up_ready.kubernetes.shell.run") as mocked_run,
        ):
            publish_registry_images(ctx)

        self.assertEqual(
            [call.args[0][1] for call in mocked_run.call_args_list],
            ["registry-build-all", "registry-mirror-all"],
        )


if __name__ == "__main__":
    unittest.main()
