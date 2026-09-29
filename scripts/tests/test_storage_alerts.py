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
            "StorageMetricsMissing": "critical",
            "HostPathVolumeHigh": "warning",
            "FilesystemShrinkingFast": "warning",
            "NodeDiskPressure": "critical",
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


class PvcUtilizationSourceTest(unittest.TestCase):
    """k3s local-path volumes are bind mounts, not filesystems.

    kubelet_volume_stats_* reports the host rootfs numbers for every such
    volume, so a recording rule built only from that source reports the node's
    disk as the contents of every PVC.
    """

    def test_ratio_prefers_the_host_textfile_measurement(self) -> None:
        rules_by_name = {
            rule["record"]: rule
            for group in yaml.safe_load(
                (RULES_DIRECTORY / "recording.rules.yml").read_text(encoding="utf-8")
            )["groups"]
            for rule in group.get("rules", [])
        }
        ratio = rules_by_name["pvc:utilization:ratio"]["expr"]
        self.assertIn("pvc:available_bytes", ratio)
        self.assertIn("pvc:capacity_bytes", ratio)
        source = rules_by_name["pvc:available_bytes"]["expr"]
        self.assertIn("ssl_proxy_host_path_used_bytes", source)
        self.assertIn("ssl_proxy_host_path_capacity_bytes", source)
        self.assertIn("kubelet_volume_stats_available_bytes", source)

    def test_pvc_days_to_full_uses_the_recorded_measurement(self) -> None:
        alerts = {rule["alert"]: rule for rule in rules("capacity.alerts.yml")}
        expr = alerts["PVCDaysToFull"]["expr"]
        self.assertIn("pvc:available_bytes", expr)
        self.assertNotIn("kubelet_volume_stats", expr)


class MetricProducerTest(unittest.TestCase):
    """Every metric an alert reads must have a producer in this repository.

    A rule whose metric has no series is silently unevaluated. That is how five
    storage alerts sat dead while the node ran out of disk.
    """

    SOURCES = ("scripts", "ops", "services", "crates", "src", "apps", "cyber-stack")
    # Metrics produced by an exporter, not by first-party code.
    EXTERNAL = {
        "absent",
        "and",
        "by",
        "clamp_min",
        "deriv",
        "predict_linear",
        "sum",
    }

    def metric_names(self, expr: str) -> set[str]:
        candidates = set(re.findall(r"[a-z_][a-z0-9_]*(?::[a-z0-9_]+)*", expr))
        skip = {
            "alertname",
            "and",
            "or",
            "unless",
            "ignoring",
            "group_left",
            "group_right",
            "on",
            "offset",
            "bool",
            "inf",
            "nan",
        }
        return {
            name
            for name in candidates
            if name not in skip
            and name not in self.EXTERNAL
            and not re.fullmatch(r"[0-9hmsy]+", name)
            and (":" in name or "_" in name)
        }

    def test_every_alert_metric_has_a_producer(self) -> None:
        corpus = ""
        for name in self.SOURCES:
            path = REPOSITORY_ROOT / name
            if not path.is_dir():
                continue
            for candidate in path.rglob("*"):
                if candidate.suffix in {".yml", ".yaml", ".sh", ".py", ".rs", ".scala", ".go"}:
                    try:
                        corpus += candidate.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
        self.assertTrue(corpus, "no first-party sources were read")

        for path in sorted(RULES_DIRECTORY.glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            for group in document.get("groups", []):
                for rule in group.get("rules", []):
                    if "alert" not in rule:
                        continue
                    for metric in sorted(self.metric_names(rule["expr"])):
                        if metric in corpus:
                            continue
                        self.fail(
                            f"{path.name}: alert {rule['alert']} reads {metric}, "
                            "which no first-party source or manifest produces"
                        )

    def test_storage_alerts_guard_their_own_producers(self) -> None:
        alerts = {rule["alert"]: rule for rule in rules("storage.alerts.yml")}
        guard = alerts["StorageMetricsMissing"]["expr"]
        for metric in (
            "docker_volume_used_bytes",
            "ssl_proxy_storage_textfile_timestamp_seconds",
            "ssl_proxy_postgres_database_bytes",
        ):
            self.assertIn(f"absent({metric})", guard, metric)

    def test_rate_alert_precedes_size_thresholds(self) -> None:
        """A sustained writer is invisible to a size threshold.

        The node lost 374 GiB in about eighty minutes. FilesystemFreeSpaceCritical
        needs 85% full, which arrived only after the node was already evicting.
        """
        alerts = {rule["alert"]: rule for rule in rules("storage.alerts.yml")}
        rate = alerts["FilesystemShrinkingFast"]
        self.assertIn("deriv(node_filesystem_avail_bytes", rate["expr"])
        self.assertIn("53687091200", rate["expr"])
        self.assertEqual(rate["labels"]["severity"], "warning")
        self.assertEqual(alerts["NodeDiskPressure"]["labels"]["severity"], "critical")
        self.assertIn('condition="DiskPressure"', alerts["NodeDiskPressure"]["expr"])


class SystemdUnitTest(unittest.TestCase):
    def test_textfile_unit_sets_required_environment(self) -> None:
        unit = (
            REPOSITORY_ROOT
            / "scripts"
            / "systemd"
            / "ssl-proxy-pv-usage-textfile.service"
        ).read_text(encoding="utf-8")
        for key in (
            "K3S_PVC_ROOT",
            "DOCKER_VOLUME_ROOT",
            "KUBECONFIG",
            "KUBERNETES_NAMESPACE",
        ):
            self.assertIn(f"Environment={key}=", unit, key)
        self.assertIn("EnvironmentFile=-/etc/default/ssl-proxy-storage", unit)

    def test_textfile_unit_uses_the_real_local_path_root(self) -> None:
        unit = (
            REPOSITORY_ROOT
            / "scripts"
            / "systemd"
            / "ssl-proxy-pv-usage-textfile.service"
        ).read_text(encoding="utf-8")
        self.assertIn("K3S_PVC_ROOT=/var/lib/rancher/k3s/storage", unit)
        self.assertNotIn("K3S_PVC_ROOT=/k3s", unit)


class AlertmanagerRoutingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.document = yaml.safe_load(
            (
                REPOSITORY_ROOT
                / "cyber-stack"
                / "base"
                / "telemetry"
                / "config"
                / "alertmanager"
                / "alertmanager.yml"
            ).read_text(encoding="utf-8")
        )

    @staticmethod
    def minutes(value: str) -> int:
        match = re.fullmatch(r"(\d+)([smh])", value)
        assert match, f"unparseable duration: {value}"
        amount, unit = int(match.group(1)), match.group(2)
        return amount * {"s": 1 / 60, "m": 1, "h": 60}[unit]

    def test_criticals_repeat_faster_than_warnings(self) -> None:
        route = self.document["route"]
        critical = [
            child
            for child in route.get("routes", [])
            if 'severity="critical"' in child.get("matchers", [])
        ]
        self.assertEqual(len(critical), 1, "expected one critical child route")
        self.assertLess(
            self.minutes(critical[0]["repeat_interval"]),
            self.minutes(route["repeat_interval"]),
            "a sustained critical must repeat faster than the default",
        )

    def test_group_keys_use_only_labels_rules_actually_set(self) -> None:
        """No rule in this repository sets an environment label."""
        route = self.document["route"]
        for key in route["group_by"]:
            with self.subTest(key=key):
                self.assertNotEqual(key, "environment")
        for rule in self.document["inhibit_rules"]:
            self.assertNotIn("environment", rule["equal"])


class StorageTextfileScriptTest(unittest.TestCase):
    def test_publishes_pvc_identity_and_capacity(self) -> None:
        script = (REPOSITORY_ROOT / "scripts" / "pv-usage-textfile.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("ssl_proxy_host_path_capacity_bytes", script)
        self.assertIn("persistentvolumeclaim=", script)
        self.assertIn("namespace=", script)
        self.assertIn("node=", script)
        self.assertIn('class="host_path"', script)

    def test_rejects_an_unparseable_capacity_instead_of_reporting_zero(self) -> None:
        script = (REPOSITORY_ROOT / "scripts" / "pv-usage-textfile.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("unparseable capacity quantity", script)


if __name__ == "__main__":
    unittest.main()
