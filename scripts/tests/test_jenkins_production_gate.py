from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class JenkinsProductionGateTest(unittest.TestCase):
    def test_registry_authority_is_fail_closed_before_validation(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        checkout = pipeline.index("checkout scm")
        authority = pipeline.index(
            "scripts/image_contract.py registry-authority --environment prod"
        )
        validation = pipeline.index("stage('Validate and test')")
        registry_guard = pipeline[checkout:validation]

        self.assertLess(checkout, authority)
        self.assertLess(authority, validation)
        self.assertIn('${CI_REGISTRY:-}', registry_guard)
        self.assertIn('[ "$CI_REGISTRY" != "$expected_registry" ]', registry_guard)
        self.assertIn("controller environment drift", registry_guard)
        self.assertIn(
            "docker compose -f docker-compose.ci.yaml up -d --no-deps "
            "--force-recreate jenkins",
            registry_guard,
        )
        self.assertNotIn("registry:5000", pipeline)

    def test_compose_derives_ci_registry_from_server_ip(self) -> None:
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        jenkins_service = compose[
            compose.index("  jenkins:\n") : compose.index("\nnetworks:")
        ]

        self.assertIn('CI_REGISTRY: "${SERVER_IP}:5000"', jenkins_service)

    def test_docker_context_is_ready_before_containerized_validation(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        preflight = pipeline.index("stage('Docker test preflight')")
        validation = pipeline.index("stage('Validate and test')")
        block = pipeline[preflight:validation]

        self.assertLess(preflight, validation)
        self.assertIn('docker context inspect "$DOCKER_CONTEXT_NAME"', block)
        self.assertIn('docker context create "$DOCKER_CONTEXT_NAME"', block)
        self.assertIn('DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version', block)

    def test_dind_can_resolve_workspace_binds_and_scala_can_start_testcontainers(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        dind = compose[
            compose.index("  jenkins-docker:\n") : compose.index("\n  jenkins:\n")
        ]
        scala = pipeline[
            pipeline.index("stage('Scala services')") : pipeline.index(
                "stage('Sensor')"
            )
        ]

        self.assertIn("- jenkins-home:/var/jenkins_home", dind)
        self.assertEqual(
            2,
            scala.count("-v /var/run/docker.sock:/var/run/docker.sock"),
        )

    def test_promotion_commit_marker_cannot_bypass_the_observer(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        classification = pipeline[
            pipeline.index("env.IS_PROMOTION_COMMIT") : pipeline.index(
                "if (env.IS_MAIN != 'true')"
            )
        ]

        self.assertIn("'[digest-promotion]'", classification)
        self.assertIn("git diff --name-only HEAD^ HEAD", classification)
        self.assertIn("marked digest promotion changed unexpected paths", classification)
        self.assertIn("exit 1", classification)

    def test_promotion_runs_in_a_clean_disposable_checkout(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        promotion = pipeline[
            pipeline.index("stage('Open digest promotion PR')") : pipeline.index(
                "stage('Observe Wiretrap production')"
            )
        ]

        self.assertIn("mktemp -d", promotion)
        self.assertIn("git clone --no-local --branch main --single-branch", promotion)
        self.assertIn("trap 'rm -rf --", promotion)
        self.assertIn('python3 scripts/promote_release.py --manifest "$manifest_path"', promotion)

    def test_pipeline_validates_before_bounded_publication(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")

        self.assertIn("timeout(time: 180, unit: 'MINUTES')", pipeline)
        validation = pipeline.index("stage('Validate and test')")
        publication = pipeline.index("stage('Publish immutable images')")
        self.assertLess(validation, publication)
        self.assertIn("--max-workers 3", pipeline[publication:])
        self.assertIn("--manifest-out", pipeline[publication:])

    def test_pipeline_opens_reviewed_digest_pr_after_publication(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        publication = pipeline.index("stage('Publish immutable images')")
        promotion = pipeline.index("stage('Open digest promotion PR')")
        self.assertLess(publication, promotion)
        self.assertIn("ssl-proxy-github-promotion-token", pipeline[promotion:])
        self.assertIn("scripts/promote_release.py", pipeline[promotion:])

    def test_delivery_validation_is_fail_closed(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        validation = pipeline[
            pipeline.index("stage('Validate and test')") : pipeline.index(
                "stage('Registry and Buildx preflight')"
            )
        ]

        self.assertIn("failFast true", validation)
        self.assertIn("make jenkins-plugin-audit", validation)
        self.assertNotIn("catchError", validation)

    def test_pipeline_aborts_superseded_builds(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")

        self.assertIn("disableConcurrentBuilds(abortPrevious: true)", pipeline)
        self.assertNotIn("disableConcurrentBuilds()", pipeline)

    def test_pipeline_verifies_octopus_pin_before_buildx_preflight(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        submodule_update = pipeline.index("git submodule update --init --recursive")
        source_integrity = pipeline.index("make octopus-source-integrity")
        buildx_preflight = pipeline.index("stage('Registry and Buildx preflight')")

        self.assertLess(submodule_update, source_integrity)
        self.assertLess(source_integrity, buildx_preflight)

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
        validation_index = pipeline.index("stage('Validate and test')")
        gate_index = pipeline.index("stage('Observe Wiretrap production')")

        self.assertGreater(gate_index, validation_index)
        gate = pipeline[gate_index:]
        self.assertIn("env.IS_PROMOTION_COMMIT == 'true'", gate)
        self.assertIn("ssl-proxy-prod-readonly-kubeconfig", gate)
        self.assertIn("variable: 'PROD_KUBECONFIG'", gate)
        self.assertIn('expected_revision="$(git rev-parse HEAD)"', gate)
        self.assertIn('KUBECONFIG="$PROD_KUBECONFIG" make production-gate', gate)
        self.assertNotIn("kubectl apply", gate)
        self.assertNotIn("argocd app sync", gate)

    def test_pipeline_refreshes_dind_tls_context_before_preflight(self) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        preflight_start = pipeline.index("stage('Registry and Buildx preflight')")
        publication_start = pipeline.index("stage('Publish immutable images')")
        preflight = pipeline[preflight_start:publication_start]

        inspect = 'docker context inspect "$DOCKER_CONTEXT_NAME"'
        remove = 'docker context rm --force "$DOCKER_CONTEXT_NAME"'
        create = 'docker context create "$DOCKER_CONTEXT_NAME"'

        self.assertIn(inspect, preflight)
        self.assertIn(remove, preflight)
        self.assertIn(create, preflight)
        self.assertLess(preflight.index(inspect), preflight.index(remove))
        self.assertLess(preflight.index(remove), preflight.index(create))
        self.assertNotIn("if ! docker context inspect", preflight)

    def test_pipeline_rejects_insufficient_inotify_before_docker_preflight(
        self,
    ) -> None:
        pipeline = (REPOSITORY_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
        preflight_start = pipeline.index("stage('Registry and Buildx preflight')")
        publication_start = pipeline.index("stage('Publish immutable images')")
        preflight = pipeline[preflight_start:publication_start]

        capacity_path = "/proc/sys/fs/inotify/max_user_instances"
        threshold = "required_inotify_instances=1024"
        invalid_value_guard = "''|*[!0-9]*)"
        insufficient_capacity_guard = (
            '[ "$current_inotify_instances" -ge "$required_inotify_instances" ]'
        )
        recovery_command = (
            "docker compose -f docker-compose.ci.yaml up -d --no-deps "
            "--force-recreate jenkins-docker"
        )
        docker_preflight = 'docker context inspect "$DOCKER_CONTEXT_NAME"'

        self.assertIn(capacity_path, preflight)
        self.assertIn(threshold, preflight)
        self.assertIn(invalid_value_guard, preflight)
        self.assertIn(insufficient_capacity_guard, preflight)
        self.assertIn(recovery_command, preflight)
        self.assertLess(
            preflight.index(capacity_path),
            preflight.index(docker_preflight),
        )
        self.assertLess(
            preflight.index(insufficient_capacity_guard),
            preflight.index(docker_preflight),
        )

    def test_credentials_binding_plugin_is_explicitly_pinned(self) -> None:
        plugins = (REPOSITORY_ROOT / "docker/jenkins/plugins.txt").read_text(
            encoding="utf-8"
        )

        self.assertRegex(
            plugins,
            re.compile(r"^credentials-binding:728\.v902a_273b_8947$", re.MULTILINE),
        )

    def test_controller_installs_complete_lock_without_latest_resolution(self) -> None:
        dockerfile = (REPOSITORY_ROOT / "docker/jenkins/Dockerfile").read_text(
            encoding="utf-8"
        )
        direct = (
            REPOSITORY_ROOT / "docker/jenkins/plugins.txt"
        ).read_text(encoding="utf-8")
        lock_path = REPOSITORY_ROOT / "docker/jenkins/plugins.lock.txt"

        self.assertEqual(8, len([line for line in direct.splitlines() if line]))
        self.assertTrue(lock_path.is_file())
        self.assertIn("COPY plugins.lock.txt", dockerfile)
        self.assertIn("--plugin-file /usr/share/jenkins/ref/plugins.lock.txt", dockerfile)
        self.assertIn("--latest=false", dockerfile)
        self.assertNotIn("COPY plugins.txt", dockerfile)

    def test_compose_tag_matches_dockerfile_controller_version(self) -> None:
        dockerfile = (REPOSITORY_ROOT / "docker/jenkins/Dockerfile").read_text(
            encoding="utf-8"
        )
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        base = re.search(r"^FROM jenkins/jenkins:([^-]+)-lts", dockerfile, re.MULTILINE)
        image = re.search(
            r"^    image: ssl-proxy-ci-jenkins:([^\s]+)$", compose, re.MULTILINE
        )

        self.assertIsNotNone(base)
        self.assertIsNotNone(image)
        self.assertEqual(base.group(1), image.group(1))

    def test_observability_plugins_and_readonly_identity_are_pinned(self) -> None:
        plugins = (REPOSITORY_ROOT / "docker/jenkins/plugins.txt").read_text(
            encoding="utf-8"
        )
        casc = (REPOSITORY_ROOT / "docker/jenkins/casc/jenkins.yaml").read_text(
            encoding="utf-8"
        )

        self.assertIn("prometheus:856.vc9e3d6e4b_b_9e", plugins)
        self.assertIn("matrix-auth:3.3", plugins)
        self.assertIn("projectMatrix:", casc)
        self.assertIn('name: "prometheus"', casc)
        self.assertIn('- "Overall/Read"', casc)
        self.assertIn('- "Metrics/View"', casc)
        self.assertIn("permissions(['Job/Read'])", casc)
        self.assertNotIn("loggedInUsersCanDoAnything", casc)

    def test_compose_mounts_prometheus_scrape_password(self) -> None:
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        environment_example = (REPOSITORY_ROOT / ".env.example").read_text(
            encoding="utf-8"
        )

        self.assertIn("      - jenkins-prometheus-password", compose)
        self.assertIn(
            "file: ${JENKINS_PROMETHEUS_PASSWORD_FILE:-./secrets/jenkins-prometheus-password}",
            compose,
        )
        self.assertIn("JENKINS_PROMETHEUS_PASSWORD_FILE=", environment_example)

    def test_observability_queries_match_captured_prometheus_fixture(self) -> None:
        fixture = (
            REPOSITORY_ROOT / "docker/jenkins/fixtures/prometheus.txt"
        ).read_text(encoding="utf-8")
        dashboard = (
            REPOSITORY_ROOT
            / "cyber-stack/base/telemetry/config/grafana/dashboards/jenkins-builds.json"
        ).read_text(encoding="utf-8")
        rules = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                REPOSITORY_ROOT
                / "cyber-stack/base/telemetry/config/prometheus/rules"
            ).glob("*.yml")
        )
        expected_metrics = {
            "default_jenkins_up",
            "default_jenkins_uptime",
            "default_jenkins_executors_available",
            "default_jenkins_executors_busy",
            "jenkins_queue_size_value",
            "jenkins_queue_blocked_value",
            "jenkins_queue_pending_value",
            "jenkins_queue_buildable_value",
            "jenkins_queue_stuck_value",
            "jenkins_job_scheduled_total",
            "jenkins_job_building_duration",
            "jenkins_job_waiting_duration",
            "jenkins_executor_in_use_value",
            "jenkins_executor_free_value",
        }

        for metric in expected_metrics:
            self.assertRegex(fixture, rf"(?m)^{metric}(?:\{{| )")
            self.assertIn(metric, dashboard + rules)

        self.assertNotIn("default_jenkins_builds_", dashboard + rules)
        self.assertNotIn("default_jenkins_queue_", dashboard + rules)

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

    def test_jcasc_declares_the_github_promotion_credential(self) -> None:
        casc = yaml.safe_load(
            (REPOSITORY_ROOT / "docker/jenkins/casc/jenkins.yaml").read_text(
                encoding="utf-8"
            )
        )
        credentials = casc["credentials"]["system"]["domainCredentials"][0][
            "credentials"
        ]
        identifiers = {
            credential_type["id"]
            for credential in credentials
            for credential_type in credential.values()
        }

        self.assertIn("ssl-proxy-github-promotion-token", identifiers)

    def test_compose_hardens_dind_inotify_capacity(self) -> None:
        compose = (REPOSITORY_ROOT / "docker-compose.ci.yaml").read_text(
            encoding="utf-8"
        )
        dind_service = compose[
            compose.index("  jenkins-docker:\n") : compose.index("\n  jenkins:\n")
        ]
        entrypoint = REPOSITORY_ROOT / "docker/jenkins/dind-entrypoint.sh"
        environment_example = (REPOSITORY_ROOT / ".env.example").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES: "
            "${JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES:-1024}",
            dind_service,
        )
        self.assertIn(
            "./docker/jenkins/dind-entrypoint.sh:"
            "/usr/local/bin/jenkins-dind-entrypoint.sh:ro",
            dind_service,
        )
        self.assertIn(
            "- /usr/local/bin/jenkins-dind-entrypoint.sh", dind_service
        )
        self.assertIn(
            "/proc/sys/fs/inotify/max_user_instances",
            entrypoint.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES=1024",
            environment_example,
        )


if __name__ == "__main__":
    unittest.main()
