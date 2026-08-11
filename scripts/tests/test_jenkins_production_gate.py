from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class JenkinsProductionGateTest(unittest.TestCase):
    def test_kubectl_is_version_and_checksum_pinned(self) -> None:
        dockerfile = (REPOSITORY_ROOT / "docker/jenkins/Dockerfile").read_text(
            encoding="utf-8"
        )

        self.assertIn("ARG KUBECTL_VERSION=1.36.3", dockerfile)
        self.assertIn(
            "ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336",
            dockerfile,
        )
        self.assertIn(
            "3d86f24401c41ae5a46ac50eef8865fe891d3647d324a0836f6c63757a126e62",
            dockerfile,
        )
        self.assertRegex(dockerfile, r'echo "\$\{KUBECTL_SHA256\}  /tmp/kubectl" \| sha256sum -c -')

    def test_pipeline_binds_readonly_kubeconfig_to_final_gate(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        validation_index = pipeline.index("stage('Validate and publish')")
        gate_index = pipeline.index("stage('Production revision gate')")

        self.assertGreater(gate_index, validation_index)
        gate = pipeline[gate_index:]
        self.assertIn("currentBuild.currentResult == 'SUCCESS'", gate)
        self.assertIn("ssl-proxy-prod-readonly-kubeconfig", gate)
        self.assertIn("variable: 'PROD_KUBECONFIG'", gate)
        self.assertIn('expected_revision="$(git rev-parse HEAD)"', gate)
        self.assertIn('KUBECONFIG="$PROD_KUBECONFIG" make production-gate', gate)
        self.assertNotIn("kubectl apply", gate)
        self.assertNotIn("argocd app sync", gate)

    def test_credentials_binding_plugin_is_explicitly_pinned(self) -> None:
        plugins = (REPOSITORY_ROOT / "docker/jenkins/plugins.txt").read_text(
            encoding="utf-8"
        )

        self.assertRegex(
            plugins,
            re.compile(r"^credentials-binding:728\.v902a_273b_8947$", re.MULTILINE),
        )

    def test_compose_mounts_required_readonly_kubeconfig_secret(self) -> None:
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        environment_example = (REPOSITORY_ROOT / ".env.example").read_text(
            encoding="utf-8"
        )
        jenkins_service = compose[
            compose.index("  jenkins:\n") : compose.index("\nnetworks:")
        ]

        self.assertIn(
            "      - ssl-proxy-prod-readonly-kubeconfig", jenkins_service
        )
        self.assertRegex(
            compose,
            re.compile(
                r"^  ssl-proxy-prod-readonly-kubeconfig:\n"
                r"    file: \$\{JENKINS_PROD_READONLY_KUBECONFIG_FILE:\?"
                r"JENKINS_PROD_READONLY_KUBECONFIG_FILE is required\}$",
                re.MULTILINE,
            ),
        )
        self.assertIn(
            "JENKINS_PROD_READONLY_KUBECONFIG_FILE=",
            environment_example,
        )

    def test_jcasc_imports_readonly_kubeconfig_as_file_credential(self) -> None:
        casc = (REPOSITORY_ROOT / "docker/jenkins/casc/jenkins.yaml").read_text(
            encoding="utf-8"
        )

        self.assertRegex(
            casc,
            re.compile(
                r'^credentials:\n'
                r"  system:\n"
                r"    domainCredentials:\n"
                r"      - credentials:\n"
                r"          - file:\n"
                r"              scope: GLOBAL\n"
                r'              id: "ssl-proxy-prod-readonly-kubeconfig"\n'
                r'              description: "[^"]+"\n'
                r'              fileName: "prod-readonly-kubeconfig"\n'
                r'              secretBytes: "\$\{readFileBase64:'
                r'/run/secrets/ssl-proxy-prod-readonly-kubeconfig\}"$',
                re.MULTILINE,
            ),
        )


if __name__ == "__main__":
    unittest.main()
