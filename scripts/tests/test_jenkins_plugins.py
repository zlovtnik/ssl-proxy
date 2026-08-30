from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import jenkins_plugins  # noqa: E402
from jenkins_plugins import PluginAuditError  # noqa: E402


def resolver_output(pins: dict[str, str]) -> str:
    lines = ["Installed plugins:", "", "Resulting plugin list:"]
    lines.extend(f"{name} {version}" for name, version in pins.items())
    lines.append("Done")
    return "\n".join(lines) + "\n"


def update_center(*warnings: dict[str, object]) -> dict[str, object]:
    return {"warnings": list(warnings)}


def warning(name: str, pattern: str) -> dict[str, object]:
    return {
        "type": "plugin",
        "name": name,
        "id": "SECURITY-1234",
        "message": "upgrade this plugin",
        "url": "https://www.jenkins.io/security/advisory/test/",
        "versions": [{"pattern": pattern}],
    }


class JenkinsPluginsTest(unittest.TestCase):
    def test_pin_parser_rejects_malformed_and_duplicate_pins(self) -> None:
        invalid = (
            "git\n",
            "git:latest\n",
            "git:1\ngit:2\n",
            "git:1:extra\n",
            "bad name:1\n",
        )

        for text in invalid:
            with self.subTest(text=text), self.assertRaises(PluginAuditError):
                jenkins_plugins.parse_pins_text(text, source="pins.txt")

    def test_resolver_parser_extracts_complete_effective_set(self) -> None:
        pins = {"dep": "2.0", "git": "5.10.1"}

        self.assertEqual(
            pins, jenkins_plugins.parse_resolver_output(resolver_output(pins))
        )

    def test_drift_reports_added_removed_and_changed_plugins(self) -> None:
        diagnostics = jenkins_plugins.describe_drift(
            {"changed": "1", "removed": "1"},
            {"added": "1", "changed": "2"},
        )

        self.assertEqual(3, len(diagnostics))
        self.assertIn("added", diagnostics[0])
        self.assertIn("removed", diagnostics[1])
        self.assertIn("changed 1 -> 2", diagnostics[2])

    def test_matching_warnings_accepts_non_vulnerable_versions(self) -> None:
        matches = jenkins_plugins.matching_warnings(
            {"git": "5.10.1"},
            update_center(
                warning("git", r"4[.].*"),
                warning("not-installed", r".*"),
            ),
        )

        self.assertEqual([], matches)

    def test_matching_warnings_finds_transitive_plugin(self) -> None:
        matches = jenkins_plugins.matching_warnings(
            {"direct": "1", "transitive": "2.3"},
            update_center(warning("transitive", r"2[.]3")),
        )

        self.assertEqual("transitive", matches[0][0])
        self.assertEqual("2.3", matches[0][1])

    def test_invalid_warning_metadata_fails_closed(self) -> None:
        invalid_documents = (
            [],
            {},
            {"warnings": {}},
            update_center({"type": "plugin", "name": "git"}),
            update_center(warning("git", "[")),
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(PluginAuditError):
                jenkins_plugins.matching_warnings({"git": "1"}, document)

    def test_resolver_uses_digest_pinned_image_and_latest_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "plugins.txt"
            dockerfile = root / "Dockerfile"
            requirements.write_text("git:5.10.1\n", encoding="utf-8")
            dockerfile.write_text(
                "FROM jenkins/jenkins:test@sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            captured: list[list[str]] = []

            def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                captured.append(command)
                return subprocess.CompletedProcess(
                    command, 0, resolver_output({"git": "5.10.1"}), ""
                )

            pins = jenkins_plugins.resolve_plugins(
                requirements, dockerfile, timeout=7, command_runner=runner
            )

        self.assertEqual({"git": "5.10.1"}, pins)
        self.assertIn("--latest=true", captured[0])
        self.assertIn("--no-download", captured[0])
        self.assertIn("--list", captured[0])
        self.assertIn("jenkins-plugin-cli", captured[0])

    def test_resolver_failures_and_timeouts_are_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "plugins.txt"
            dockerfile = root / "Dockerfile"
            requirements.write_text("git:1\n", encoding="utf-8")
            dockerfile.write_text(
                "FROM example.test/jenkins@sha256:" + "b" * 64 + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PluginAuditError, "exit 9"):
                jenkins_plugins.resolve_plugins(
                    requirements,
                    dockerfile,
                    command_runner=lambda command, **kwargs: subprocess.CompletedProcess(
                        command, 9, "", "resolver broke"
                    ),
                )

            def timeout(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                raise subprocess.TimeoutExpired(command, 3)

            with self.assertRaisesRegex(PluginAuditError, "timed out"):
                jenkins_plugins.resolve_plugins(
                    requirements, dockerfile, timeout=3, command_runner=timeout
                )

    def test_fetch_failure_is_actionable(self) -> None:
        def failing_opener(*_: object, **__: object) -> object:
            raise urllib.error.URLError("offline")

        with self.assertRaisesRegex(PluginAuditError, "cannot fetch"):
            jenkins_plugins.fetch_update_center(
                "https://updates.jenkins.io/update-center.actual.json",
                opener=failing_opener,
            )

    def test_audit_accepts_exact_resolution_without_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "plugins.txt"
            lock = root / "plugins.lock.txt"
            dockerfile = root / "Dockerfile"
            requirements.write_text("direct:1\n", encoding="utf-8")
            lock.write_text("dependency:2\ndirect:1\n", encoding="utf-8")
            dockerfile.write_text(
                "FROM example.test/jenkins@sha256:" + "c" * 64 + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(
                jenkins_plugins,
                "resolve_plugins",
                return_value={"dependency": "2", "direct": "1"},
            ), mock.patch.object(
                jenkins_plugins, "fetch_update_center", return_value=update_center()
            ):
                jenkins_plugins.audit(
                    requirements, lock, dockerfile, "https://example.test", 5, 5
                )

    def test_audit_rejects_security_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "plugins.txt"
            lock = root / "plugins.lock.txt"
            dockerfile = root / "Dockerfile"
            requirements.write_text("direct:1\n", encoding="utf-8")
            lock.write_text("dependency:2\ndirect:1\n", encoding="utf-8")
            dockerfile.write_text(
                "FROM example.test/jenkins@sha256:" + "d" * 64 + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(
                jenkins_plugins,
                "resolve_plugins",
                return_value={"dependency": "2", "direct": "1"},
            ), mock.patch.object(
                jenkins_plugins,
                "fetch_update_center",
                return_value=update_center(warning("dependency", "2")),
            ), self.assertRaisesRegex(PluginAuditError, "security warning"):
                jenkins_plugins.audit(
                    requirements, lock, dockerfile, "https://example.test", 5, 5
                )


if __name__ == "__main__":
    unittest.main()
