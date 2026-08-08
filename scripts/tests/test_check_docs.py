from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "check-docs.py"
SPEC = importlib.util.spec_from_file_location("check_docs", MODULE_PATH)
assert SPEC and SPEC.loader
check_docs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_docs
SPEC.loader.exec_module(check_docs)


class DocsCheckTest(unittest.TestCase):
    def make_repo(self, readme: str = "# Test\n") -> Path:
        self.addCleanup(self._cleanup)
        root = Path(tempfile.mkdtemp(prefix="docs-check-"))
        self._roots.append(root)
        self.git(root, "init", "-q")
        self.git(root, "config", "user.name", "Docs Test")
        self.git(root, "config", "user.email", "docs@example.invalid")
        (root / "docs").mkdir()
        (root / "README.md").write_text(readme, encoding="utf-8")
        (root / "docs/readme-inventory.txt").write_text("README.md\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "fixture")
        return root

    def setUp(self) -> None:
        self._roots: list[Path] = []

    def _cleanup(self) -> None:
        if self._roots:
            shutil.rmtree(self._roots.pop())

    @staticmethod
    def git(root: Path, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True
        ).strip()

    def errors(self, root: Path) -> list[str]:
        return check_docs.check_repository(root)

    def test_missing_and_extra_readmes_are_reported(self) -> None:
        root = self.make_repo()
        (root / "extra").mkdir()
        (root / "extra/README.md").write_text("# Extra\n", encoding="utf-8")
        (root / "docs/readme-inventory.txt").write_text(
            "README.md\nmissing/README.md\n", encoding="utf-8"
        )
        self.git(root, "add", ".")
        errors = self.errors(root)
        self.assertTrue(any("missing/README.md" in error for error in errors))
        self.assertTrue(any("extra/README.md" in error for error in errors))

    def test_unmapped_gitlink_is_reported(self) -> None:
        root = self.make_repo()
        child = root / "child"
        child.mkdir()
        self.git(child, "init", "-q")
        self.git(child, "config", "user.name", "Docs Test")
        self.git(child, "config", "user.email", "docs@example.invalid")
        (child / "README.md").write_text("# Child\n", encoding="utf-8")
        self.git(child, "add", "README.md")
        self.git(child, "commit", "-qm", "child")
        oid = self.git(child, "rev-parse", "HEAD")
        self.git(root, "update-index", "--add", "--cacheinfo", f"160000,{oid},child")
        errors = self.errors(root)
        self.assertTrue(any("no .gitmodules mapping" in error for error in errors))

    def test_broken_link_in_non_markdown_submodule_document_is_reported(self) -> None:
        root = self.make_repo()
        child = root / "child"
        child.mkdir()
        self.git(child, "init", "-q")
        self.git(child, "config", "user.name", "Docs Test")
        self.git(child, "config", "user.email", "docs@example.invalid")
        (child / "guide.rst").write_text("[missing](nope.md)\n", encoding="utf-8")
        self.git(child, "add", "guide.rst")
        self.git(child, "commit", "-qm", "child")
        oid = self.git(child, "rev-parse", "HEAD")
        (child / "guide.rst").write_text("Fixed after pin\n", encoding="utf-8")
        (root / ".gitmodules").write_text(
            '[submodule "child"]\n'
            "\tpath = child\n"
            "\turl = ../child\n",
            encoding="utf-8",
        )
        self.git(root, "add", ".gitmodules")
        self.git(root, "update-index", "--add", "--cacheinfo", f"160000,{oid},child")

        errors = self.errors(root)

        self.assertTrue(
            any(
                "child/guide.rst" in error and "broken local link" in error
                for error in errors
            )
        )

    def test_broken_relative_path_is_reported(self) -> None:
        root = self.make_repo("[missing](docs/nope.md)\n")
        self.assertTrue(any("broken local link" in error for error in self.errors(root)))

    def test_repository_escape_is_rejected_before_existence_check(self) -> None:
        root = self.make_repo("[outside](../outside.md)\n")
        errors = self.errors(root)
        self.assertTrue(any("local link escapes repository" in error for error in errors))
        self.assertFalse(any("broken local link" in error for error in errors))

    def test_root_relative_and_same_file_targets_are_accepted(self) -> None:
        root = self.make_repo(
            "# Test\n\n[root](/README.md#test)\n[same](#test)\n"
        )
        self.assertEqual([], self.errors(root))

    def test_invalid_anchor_is_reported(self) -> None:
        root = self.make_repo("[target](docs/target.md#missing)\n")
        (root / "docs/target.md").write_text("# Present\n", encoding="utf-8")
        self.git(root, "add", "docs/target.md")
        self.assertTrue(any("invalid local anchor" in error for error in self.errors(root)))

    def test_explicit_html_anchor_is_accepted(self) -> None:
        root = self.make_repo("[target](docs/target.md#stable)\n")
        (root / "docs/target.md").write_text(
            '<a id="stable"></a>\n# Display heading\n', encoding="utf-8"
        )
        self.git(root, "add", "docs/target.md")
        self.assertEqual([], self.errors(root))

    def test_external_urls_are_ignored(self) -> None:
        root = self.make_repo(
            "[web](https://example.invalid/nope#missing)\n"
            "[mail](mailto:ops@example.invalid)\n"
        )
        self.assertEqual([], self.errors(root))

    def test_links_in_fenced_code_are_ignored(self) -> None:
        root = self.make_repo(
            "# Test\n\n```markdown\n[not a link](missing.md#missing)\n```\n"
        )
        self.assertEqual([], self.errors(root))

    def test_link_shaped_inline_code_is_ignored(self) -> None:
        root = self.make_repo("Use `Semaphore[IO](poolSize)` for bounds.\n")
        self.assertEqual([], self.errors(root))

    def test_all_tracked_markdown_is_checked_for_deployment_policy(self) -> None:
        root = self.make_repo()
        (root / "notes.md").write_text(
            "# Operations\n\nUse Flux CD for Kubernetes.\n", encoding="utf-8"
        )
        self.git(root, "add", "notes.md")
        errors = self.errors(root)
        self.assertTrue(any("notes.md" in error for error in errors))

    def test_mutating_kubectl_is_rejected_but_read_only_is_allowed(self) -> None:
        root = self.make_repo(
            "# Operations\n\n"
            "`kubectl get pods` is diagnostic.\n\n"
            "Do not run `kubectl patch deployment example`.\n"
        )
        errors = self.errors(root)
        self.assertEqual(1, sum("mutating kubectl" in error for error in errors))

    def test_mutating_kubectl_with_short_namespace_flag_is_rejected(self) -> None:
        root = self.make_repo(
            "# Operations\n\nDo not run `kubectl -n ssl-proxy apply -k overlay`.\n"
        )
        errors = self.errors(root)
        self.assertEqual(1, sum("mutating kubectl" in error for error in errors))

    def test_retained_chart_path_is_allowed_but_prose_helm_is_rejected(self) -> None:
        allowed = self.make_repo(
            "# Compatibility\n\nSee `helm/ssl-proxy/charts/redpanda/templates/statefulset.yaml`.\n"
        )
        self.assertEqual([], self.errors(allowed))

        rejected = self.make_repo("# Operations\n\nDeploy the stack with Helm.\n")
        errors = self.errors(rejected)
        self.assertTrue(any("deployment technology" in error for error in errors))

    def test_txt_documents_remain_in_policy_scope(self) -> None:
        root = self.make_repo()
        (root / "notes.txt").write_text("Deploy the stack with Helm.\n", encoding="utf-8")
        self.git(root, "add", "notes.txt")
        errors = self.errors(root)
        self.assertTrue(any("notes.txt" in error for error in errors))

    def test_compose_is_limited_to_local_development_sections(self) -> None:
        allowed = self.make_repo(
            "# Project\n\n## Local development\n\nRun `docker compose up`.\n"
        )
        self.assertEqual([], self.errors(allowed))

        rejected = self.make_repo(
            "# Project\n\n## Operations\n\nRun `docker compose up`.\n"
        )
        errors = self.errors(rejected)
        self.assertTrue(any("local-development headings" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
