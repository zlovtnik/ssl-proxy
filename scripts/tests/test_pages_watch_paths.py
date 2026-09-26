from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pages_watch_paths import watch_paths_patch  # noqa: E402


def migrator_project() -> dict:
    return {
        "name": "ssl-proxy-migrator",
        "source": {
            "type": "github",
            "config": {
                "owner": "zlovtnik",
                "repo_name": "ssl-proxy",
                "production_branch": "main",
                "production_deployments_enabled": True,
                "preview_deployment_setting": "none",
                "path_includes": ["apps/schema-migrator/schema-migrator-ui/*"],
                "path_excludes": [],
            },
        },
    }


class PagesWatchPathsTest(unittest.TestCase):
    def test_nested_ui_rule_misses_the_parent_gitlink_update(self) -> None:
        project = migrator_project()
        before = copy.deepcopy(project)

        patch = watch_paths_patch(project, "ssl-proxy-migrator")

        self.assertEqual(
            ["apps/schema-migrator/schema-migrator-ui/*", "apps/schema-migrator", ".gitmodules"],
            patch["source"]["config"]["path_includes"],
        )
        self.assertEqual("none", patch["source"]["config"]["preview_deployment_setting"])
        self.assertEqual(before, project)
        project.update(patch)
        self.assertEqual({}, watch_paths_patch(project, "ssl-proxy-migrator"))

    def test_search_watch_paths_already_cover_its_submodule(self) -> None:
        project = migrator_project()
        project["name"] = "ssl-proxy-search"
        project["source"]["config"]["path_includes"] = ["apps/integration-console", ".gitmodules"]

        self.assertEqual({}, watch_paths_patch(project, "ssl-proxy-search"))

    def test_wildcard_includes_do_not_need_repair(self) -> None:
        project = migrator_project()
        project["source"]["config"]["path_includes"] = ["*"]

        self.assertEqual({}, watch_paths_patch(project, "ssl-proxy-migrator"))

    def test_exclusions_override_includes(self) -> None:
        project = migrator_project()
        project["source"]["config"]["path_excludes"] = ["apps/*"]

        with self.assertRaisesRegex(ValueError, "exclusions block apps/schema-migrator"):
            watch_paths_patch(project, "ssl-proxy-migrator")

    def test_wrong_repository_or_disabled_deployments_are_rejected(self) -> None:
        for field, value in (
            ("repo_name", "another-repo"),
            ("production_branch", "staging"),
            ("production_deployments_enabled", False),
        ):
            with self.subTest(field=field):
                project = migrator_project()
                project["source"]["config"][field] = value
                with self.assertRaises(ValueError):
                    watch_paths_patch(project, "ssl-proxy-migrator")


if __name__ == "__main__":
    unittest.main()
