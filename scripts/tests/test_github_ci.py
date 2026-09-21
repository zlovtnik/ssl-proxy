from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class GitHubCiTest(unittest.TestCase):
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
