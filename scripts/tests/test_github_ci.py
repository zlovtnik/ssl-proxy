from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class GitHubCiTest(unittest.TestCase):
    def test_search_contract_job_requires_database_and_pinned_revision(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text()
        search = workflow[workflow.index("  atheros-search-contracts:") : workflow.index("  documentation:")]
        self.assertIn("go-version: '1.26.x'", search)
        self.assertIn("submodules: recursive", search)
        self.assertIn("git rev-parse HEAD:apps/integration-console", search)
        self.assertIn("make atheros-search-stack-contract", search)
        self.assertIn("make atheros-search-db-contract", search)
        self.assertNotIn("continue-on-error", search)
        jenkins = (REPOSITORY_ROOT / "Jenkinsfile").read_text()
        stage = jenkins[jenkins.index("stage('Atheros search contracts')"):jenkins.index("stage('Schema migrator')")]
        self.assertIn("bash scripts/ci/atheros-search-contracts.sh", stage)
        stage = (REPOSITORY_ROOT / "scripts/ci/atheros-search-contracts.sh").read_text()
        stage += (REPOSITORY_ROOT / "scripts/ci/tasks/atheros-search-contracts-1.sh").read_text()
        self.assertNotIn("SUBMODULE_CI_READY", stage)
        self.assertIn("SHOULD_RUN_ATHEROS_SEARCH_CONTRACTS", stage)
        self.assertIn("make atheros-search-db-contract", stage)

    def test_octopus_job_enforces_and_archives_test_reports(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        octopus = workflow[workflow.index("  octopus:\n") :]

        self.assertIn('OCTOPUS_REQUIRE_DOCKER: "true"', octopus)
        self.assertIn(
            'sbt scalafmtCheckAll "scalafixAll --check" test jacoco', octopus
        )
        self.assertIn("python3 scripts/check_coverage.py", octopus)
        self.assertIn("uses: actions/upload-artifact@v4", octopus)
        self.assertIn("if: ${{ !cancelled() }}", octopus)
        self.assertIn("services/octopus/target/scala-3.3.8/jacoco/report/", octopus)
        self.assertIn("services/octopus/target/cucumber/", octopus)


if __name__ == "__main__":
    unittest.main()
