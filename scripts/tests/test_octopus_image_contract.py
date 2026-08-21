from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from octopus_image_contract import (  # noqa: E402
    ContractError,
    OCTOPUS_REVISION_LABEL,
    PARENT_REVISION_LABEL,
    check_jar,
    check_labels,
    source_revisions,
)


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


class OctopusImageContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.octopus = self.root / "services" / "octopus"
        self.octopus.mkdir(parents=True)
        git(self.octopus, "init", "-q")
        git(self.octopus, "config", "user.email", "test@example.com")
        git(self.octopus, "config", "user.name", "Test")
        (self.octopus / "source.scala").write_text("object Source\n", encoding="utf-8")
        git(self.octopus, "add", "source.scala")
        git(self.octopus, "commit", "-qm", "octopus")
        self.octopus_commit = git(self.octopus, "rev-parse", "HEAD")

        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")
        git(
            self.root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.octopus_commit},services/octopus",
        )
        git(self.root, "commit", "-qm", "parent")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_jar(self, entries: dict[str, bytes]) -> Path:
        path = self.root / "octopus.jar"
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)
        return path

    def test_source_integrity_accepts_exact_clean_pin(self) -> None:
        parent, octopus = source_revisions(self.root)

        self.assertEqual(git(self.root, "rev-parse", "HEAD"), parent)
        self.assertEqual(self.octopus_commit, octopus)

    def test_source_integrity_rejects_dirty_parent_and_octopus(self) -> None:
        (self.root / "untracked.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "parent worktree is not clean"):
            source_revisions(self.root)
        (self.root / "untracked.txt").unlink()

        (self.octopus / "source.scala").write_text("object Changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "Octopus worktree is not clean"):
            source_revisions(self.root)

    def test_source_integrity_rejects_checkout_that_differs_from_pin(self) -> None:
        (self.octopus / "source.scala").write_text("object NewSource\n", encoding="utf-8")
        git(self.octopus, "add", "source.scala")
        git(self.octopus, "commit", "-qm", "new octopus")

        with self.assertRaisesRegex(ContractError, "does not match the parent submodule pin"):
            source_revisions(self.root)

    def test_jar_accepts_current_contract_and_rejects_cutover_classes(self) -> None:
        current = self.write_jar(
            {"com/sslproxy/coordinator/config/AppConfigValidation.class": b"current"}
        )
        check_jar(current)

        obsolete = self.write_jar(
            {"com/sslproxy/coordinator/config/CutoverConfig.class": b"obsolete"}
        )
        with self.assertRaisesRegex(ContractError, "obsolete cutover classes"):
            check_jar(obsolete)

    def test_jar_rejects_obsolete_replication_and_tls_validation(self) -> None:
        for marker in (
            b"kafka.topic-replication-factor must be between 3 and 32767",
            b"tidb.ssl-mode must be VERIFY_IDENTITY",
        ):
            with self.subTest(marker=marker):
                jar = self.write_jar(
                    {"com/sslproxy/coordinator/config/AppConfig$.class": marker}
                )
                with self.assertRaisesRegex(
                    ContractError, "obsolete replication/TLS validation"
                ):
                    check_jar(jar)

    def test_labels_must_match_both_source_revisions(self) -> None:
        labels = {
            PARENT_REVISION_LABEL: "parent-sha",
            OCTOPUS_REVISION_LABEL: "octopus-sha",
        }
        check_labels(labels, "parent-sha", "octopus-sha")

        labels[OCTOPUS_REVISION_LABEL] = "wrong"
        with self.assertRaisesRegex(ContractError, "OCI label mismatch"):
            check_labels(labels, "parent-sha", "octopus-sha")


if __name__ == "__main__":
    unittest.main()
