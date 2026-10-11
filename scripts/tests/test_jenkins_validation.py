from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class JenkinsValidationTest(unittest.TestCase):
    def test_metrics_race_checks_use_process_local_layout_helper(self) -> None:
        task = (REPOSITORY_ROOT / "scripts/ci/tasks/octopus-metrics-1.sh").read_text()
        self.assertIn("-DMETRICS_TSAN=ON", task)
        self.assertIn("sh /workspace/scripts/ci/tasks/metrics-tsan-test.sh /tmp/metrics-tsan", task)
        self.assertNotIn("sysctl", task)
        self.assertNotIn("continue-on-error", task)

    def test_search_contract_job_requires_database_and_pinned_revision(self) -> None:
        jenkins = (REPOSITORY_ROOT / "Jenkinsfile").read_text()
        stage = jenkins[jenkins.index("stage('Atheros search contracts')"):jenkins.index("stage('Schema migrator')")]
        self.assertIn("bash scripts/ci/atheros-search-contracts.sh", stage)
        runner = (REPOSITORY_ROOT / "scripts/ci/atheros-search-contracts.sh").read_text()
        task = (REPOSITORY_ROOT / "scripts/ci/tasks/atheros-search-contracts-1.sh").read_text()
        self.assertIn("git rev-parse HEAD:apps/integration-console", runner)
        self.assertIn("golang:1.26-bookworm", runner)
        self.assertNotIn("SUBMODULE_CI_READY", runner)
        self.assertIn("SHOULD_RUN_ATHEROS_SEARCH_CONTRACTS", runner)
        self.assertIn("make atheros-search-stack-contract", task)
        self.assertIn("make atheros-search-db-contract", task)

    def test_octopus_job_enforces_and_archives_test_reports(self) -> None:
        jenkins = (REPOSITORY_ROOT / "Jenkinsfile").read_text()
        task = (REPOSITORY_ROOT / "scripts/ci/tasks/octopus-1.sh").read_text()
        runner = (REPOSITORY_ROOT / "scripts/ci/octopus.sh").read_text()
        self.assertIn("OCTOPUS_REQUIRE_DOCKER=true", task)
        self.assertIn("jacoco", task)
        self.assertIn('scalafmtCheckAll "scalafixAll --check" jacoco assembly', task)
        self.assertIn("python3 scripts/check_coverage.py", task)
        self.assertIn("python3 ../../scripts/octopus_image_contract.py jar", task)
        self.assertIn("/jacoco/report", runner)
        self.assertIn("/target/cucumber", runner)
        self.assertIn("archiveArtifacts artifacts: 'artifacts/octopus-coverage/**'", jenkins)

    def test_delivery_checks_retain_database_contract_validation(self) -> None:
        jenkins = (REPOSITORY_ROOT / "Jenkinsfile").read_text()
        delivery = jenkins[jenkins.index("stage('Delivery contracts')"):jenkins.index("stage('Keycloak login layout')")]
        for script in ("check-runtime-datastores.py", "check-postgres-schema-contract.py",
                       "check-column-limits.sh", "test-postgres-schema-executor-integration.sh"):
            self.assertIn(script, delivery)
        self.assertIn('TMPDIR="$WORKSPACE"', delivery)


if __name__ == "__main__":
    unittest.main()
