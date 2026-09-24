from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RULES_DIRECTORY = (
    REPOSITORY_ROOT
    / "cyber-stack"
    / "base"
    / "telemetry"
    / "config"
    / "prometheus"
    / "rules"
)
RUNBOOK_URL = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/main/(?P<path>[^#]+)(?:#(?P<anchor>.+))?$")

SPEC = importlib.util.spec_from_file_location(
    "check_docs_for_alerts", REPOSITORY_ROOT / "scripts" / "check-docs.py"
)
assert SPEC and SPEC.loader
check_docs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_docs
SPEC.loader.exec_module(check_docs)


def rules(path: str) -> list[dict]:
    document = yaml.safe_load((RULES_DIRECTORY / path).read_text(encoding="utf-8"))
    return [
        rule
        for group in document["groups"]
        for rule in group.get("rules", [])
    ]


class StorageAlertsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.alerts = {rule["alert"]: rule for rule in rules("storage.alerts.yml")}

    def test_expected_alerts_exist_with_severities(self) -> None:
        expected = {
            "RedpandaTopicLogBytesHigh": "warning",
            "RedpandaTopicLogBytesCritical": "critical",
            "RegistryVolumeHigh": "warning",
            "JenkinsDinDVolumeHigh": "warning",
            "PostgresDatabaseSizeHigh": "warning",
            "PostgresRelationSizeHigh": "warning",
            "StorageTextfileStale": "warning",
        }
        self.assertEqual(set(self.alerts), set(expected))
        for name, severity in expected.items():
            self.assertEqual(
                self.alerts[name]["labels"]["severity"], severity, name
            )

    def test_workmap_budgets_are_encoded(self) -> None:
        self.assertIn("67108864000", self.alerts["RedpandaTopicLogBytesHigh"]["expr"])
        self.assertIn("96636764160", self.alerts["RedpandaTopicLogBytesCritical"]["expr"])
        self.assertIn("16106127360", self.alerts["RegistryVolumeHigh"]["expr"])
        self.assertIn("32212254720", self.alerts["JenkinsDinDVolumeHigh"]["expr"])
        self.assertIn("161061273600", self.alerts["PostgresDatabaseSizeHigh"]["expr"])

    def test_alerts_wait_before_firing(self) -> None:
        for name, rule in self.alerts.items():
            duration = rule.get("for", "")
            self.assertRegex(duration, r"^\d+m$", name)
            self.assertNotEqual(duration, "0m", name)

    def test_alerts_point_at_the_disk_runbook(self) -> None:
        for name, rule in self.alerts.items():
            self.assertIn(
                "docs/runbooks/disk-full.md",
                rule["annotations"]["runbook_url"],
                name,
            )


class FilesystemThresholdTest(unittest.TestCase):
    def test_warning_and_critical_thresholds(self) -> None:
        alerts = {rule["alert"]: rule for rule in rules("infrastructure.rules.yml")}
        warning = alerts["FilesystemFreeSpaceWarning"]
        critical = alerts["FilesystemFreeSpaceCritical"]
        self.assertIn("> 0.75", warning["expr"])
        self.assertNotIn("0.85", warning["expr"].split("> 0.75")[0])
        self.assertIn("> 0.85", critical["expr"])
        self.assertNotIn("0.92", critical["expr"])
        self.assertEqual(warning["labels"]["severity"], "warning")
        self.assertEqual(critical["labels"]["severity"], "critical")


class AlertRegistrationTest(unittest.TestCase):
    def test_storage_rules_are_registered_with_the_rules_config_map(self) -> None:
        kustomization = (
            REPOSITORY_ROOT / "cyber-stack" / "base" / "telemetry" / "kustomization.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "storage.alerts.yml=config/prometheus/rules/storage.alerts.yml",
            kustomization,
        )

    def test_every_runbook_url_resolves_in_the_repository(self) -> None:
        checked = 0
        for path in sorted(RULES_DIRECTORY.glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            for group in document.get("groups", []):
                for rule in group.get("rules", []):
                    url = rule.get("annotations", {}).get("runbook_url")
                    if not url:
                        continue
                    match = RUNBOOK_URL.match(url)
                    self.assertIsNotNone(match, f"{path.name}: {rule['alert']}: {url}")
                    target = REPOSITORY_ROOT / match.group("path")
                    self.assertTrue(
                        target.is_file(),
                        f"{path.name}: {rule['alert']} points at a missing file: {url}",
                    )
                    anchor = match.group("anchor")
                    if anchor:
                        text = target.read_text(encoding="utf-8")
                        self.assertIn(
                            anchor,
                            check_docs.anchors_for(text),
                            f"{path.name}: {rule['alert']} has a dead anchor: {url}",
                        )
                    checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
