from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import json
import zipfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from octopus_image_contract import (  # noqa: E402
    ContractError,
    NATIVE_PATH,
    OCTOPUS_REVISION_LABEL,
    PARENT_REVISION_LABEL,
    check_jar,
    check_image,
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
        (self.root / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
        git(
            self.root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.octopus_commit},services/octopus",
        )
        git(self.root, "add", ".gitignore")
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

    def test_native_source_requires_the_rust_gitlink(self) -> None:
        with self.assertRaisesRegex(ContractError, "services/octopus-rs is not a pinned submodule"):
            source_revisions(self.root, NATIVE_PATH)

    def test_native_image_checks_pinned_labels_binary_and_entrypoint(self) -> None:
        labels = {PARENT_REVISION_LABEL: "parent", OCTOPUS_REVISION_LABEL: "rust"}
        config = {"Config": {"Entrypoint": ["/app/octopus"], "Labels": labels},
                  "Architecture": "amd64", "Os": "linux", "Id": "image-id"}
        header = bytearray(20)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[18:20] = b"\x3e\x00"

        def docker(*args, **kwargs):
            if args[:2] == ("image", "inspect"):
                return json.dumps([config])
            if args[0] == "cp":
                Path(args[2]).write_bytes(header)
            if args[0] == "run":
                self.assertEqual(args[-1], "image-id")
                return "PostgreSQL sink disabled (set POSTGRES_ENABLED=true to enable)"
            return "container"

        bad_checksum = "Octopus: Invalid Octopus configuration: postgres.manifest-sha-256 must be 64 lowercase hexadecimal characters"
        with patch("octopus_image_contract.source_revisions", return_value=("parent", "rust")) as revisions, \
             patch("octopus_image_contract._docker", side_effect=docker) as daemon, \
             patch("octopus_image_contract.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", bad_checksum)):
            self.assertEqual(check_image("tag", self.root, native=True), ("parent", "rust"))
            revisions.assert_called_once_with(self.root, NATIVE_PATH)
            header[18] = 0
            with self.assertRaisesRegex(ContractError, "x86-64 ELF"):
                check_image("tag", self.root, native=True)
            daemon.assert_called_with("rm", "-f", "container", capture=False)
            config["Config"]["Entrypoint"] = ["java"]
            with self.assertRaisesRegex(ContractError, "entrypoint"):
                check_image("tag", self.root, native=True)

    def test_source_integrity_rejects_dirty_parent_and_octopus(self) -> None:
        (self.root / "untracked.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "parent worktree is not clean"):
            source_revisions(self.root)
        (self.root / "untracked.txt").unlink()

        (self.octopus / "source.scala").write_text("object Changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "Octopus worktree is not clean"):
            source_revisions(self.root)

    def test_source_integrity_accepts_ignored_ci_artifacts(self) -> None:
        artifact = self.root / "artifacts" / "octopus-coverage" / "jacoco.xml"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("coverage", encoding="utf-8")

        parent, octopus = source_revisions(self.root)

        self.assertEqual(git(self.root, "rev-parse", "HEAD"), parent)
        self.assertEqual(self.octopus_commit, octopus)

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
            b"postgres.ssl-mode must be VERIFY_IDENTITY",
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
