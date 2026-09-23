from __future__ import annotations

import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from classify_changes import SUBMODULE_IMAGES, classify_paths, classify_repository, env_lines  # noqa: E402


class ClassifyChangesTest(unittest.TestCase):
    def bumped(self, *paths: str) -> dict[str, bool]:
        return {path: path in paths for path in SUBMODULE_IMAGES}

    def test_octopus_gitlink_bump_selects_coordinator_only(self) -> None:
        result = classify_paths(
            {"services/octopus", "services/octopus/src/ignored.scala"},
            self.bumped("services/octopus"), full=False
        )
        self.assertEqual(["java-coordinator"], result["changedServices"])
        self.assertEqual([], result["changedMainPaths"])
        self.assertTrue(result["tests"]["octopus"])

    def test_integration_console_bump_selects_both_images(self) -> None:
        result = classify_paths(
            {"apps/integration-console"},
            self.bumped("apps/integration-console"), full=False,
        )
        self.assertEqual(["atheros-search", "atheros-search-ui"], result["changedServices"])
        self.assertTrue(result["tests"]["atheros_search"])

    def test_sensor_and_schema_paths_do_not_publish_unrelated_images(self) -> None:
        result = classify_paths(
            {"services/atheros-sensor/src/main.rs", "sql/postgres/contracts/manifest.txt"},
            self.bumped(), full=False,
        )
        self.assertEqual(["atheros-sensor", "postgres-runtime-schema"], result["changedServices"])
        self.assertTrue(result["tests"]["sensor"])
        self.assertIn("SHOULD_RUN_OCTOPUS=false", env_lines(result))

    def test_first_commit_selects_everything(self) -> None:
        result = classify_paths(set(), self.bumped(*SUBMODULE_IMAGES), full=True)
        self.assertEqual(8, len(result["changedServices"]))
        self.assertTrue(all(result["tests"].values()))
        self.assertTrue(result["publishRedpandaMaint"])

    def test_repository_range_includes_every_commit_since_successful_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def run(*args: str) -> str:
                return subprocess.run(
                    ("git", *args), cwd=root, check=True, capture_output=True, text=True
                ).stdout.strip()

            run("init")
            run("config", "user.name", "CI test")
            run("config", "user.email", "ci@example.test")
            (root / "README").write_text("first\n")
            run("add", "README")
            run("commit", "-m", "first")
            first = run("rev-parse", "HEAD")
            (root / "services/platform-sync").mkdir(parents=True)
            (root / "services/platform-sync/main.go").write_text("package main\n")
            run("add", ".")
            run("commit", "-m", "platform")
            (root / "sql/postgres").mkdir(parents=True)
            (root / "sql/postgres/schema.sql").write_text("select 1;\n")
            run("add", ".")
            run("commit", "-m", "schema")

            result = classify_repository(root, base=first)
            self.assertEqual(first, result["baseRevision"])
            self.assertTrue(result["tests"]["platform_sync"])
            self.assertEqual(["postgres-runtime-schema"], result["changedServices"])
            self.assertEqual(2, len(result["changedMainPaths"]))
            first_build = classify_repository(root, base="missing")
            self.assertEqual(8, len(first_build["changedServices"]))
            self.assertIn("services/platform-sync/main.go", first_build["changedMainPaths"])


if __name__ == "__main__":
    unittest.main()
