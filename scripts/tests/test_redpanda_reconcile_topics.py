from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "ops" / "redpanda" / "reconcile_topics.py"
SPEC = importlib.util.spec_from_file_location("reconcile_topics", MODULE_PATH)
assert SPEC and SPEC.loader
reconcile_topics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconcile_topics
SPEC.loader.exec_module(reconcile_topics)


PROD_MANIFEST = ROOT / "cyber-stack/base/platform-config/configmap.yaml"
DEV_MANIFEST = ROOT / "docker/redpanda/topics.manifest"


class FakeClient:
    def __init__(self, live: dict[str, reconcile_topics.LiveTopic]) -> None:
        self.live = live
        self.altered: list[tuple[str, dict[str, str]]] = []

    def describe(self, topic: str) -> reconcile_topics.LiveTopic:
        return self.live[topic]

    def alter(self, topic: str, settings: dict[str, str]) -> None:
        self.altered.append((topic, settings))


class ManifestTest(unittest.TestCase):
    def test_tracked_manifests_are_bounded(self) -> None:
        for path in (PROD_MANIFEST, DEV_MANIFEST):
            with self.subTest(manifest=path):
                specs = reconcile_topics.load_manifest(path)
                self.assertTrue(specs)
                for spec in specs:
                    self.assertGreater(spec.retention_bytes, 0)
                    self.assertGreaterEqual(spec.retention_ms, 0)
                    self.assertGreaterEqual(spec.partitions, 1)

    def test_wireless_audit_budget_matches_the_workmap(self) -> None:
        spec = next(
            item
            for item in reconcile_topics.load_manifest(PROD_MANIFEST)
            if item.topic == "wireless.audit"
        )
        self.assertEqual(604800000, spec.retention_ms)
        self.assertEqual(spec.partitions * spec.retention_bytes, 64424509440)

    def test_unbounded_topic_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "topics.manifest"
            manifest.write_text("wireless.audit|3|1|-1|-1\n", encoding="utf-8")
            with self.assertRaises(reconcile_topics.ReconcileError):
                reconcile_topics.load_manifest(manifest)

    def test_missing_configmap_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "topics.yaml"
            manifest.write_text("kind: ConfigMap\n", encoding="utf-8")
            with self.assertRaises(reconcile_topics.ReconcileError):
                reconcile_topics.load_manifest(manifest)


class SummaryParsingTest(unittest.TestCase):
    def test_parses_both_summary_shapes(self) -> None:
        self.assertEqual(24, reconcile_topics._summary_int("PARTITIONS 24", "PARTITIONS"))
        self.assertEqual(
            3,
            reconcile_topics._summary_int(
                "NAME PARTITIONS\nwireless.audit 3\n", "PARTITIONS"
            ),
        )
        self.assertIsNone(reconcile_topics._summary_int("nothing here", "PARTITIONS"))


class DiffTest(unittest.TestCase):
    def _spec(self) -> reconcile_topics.TopicSpec:
        return reconcile_topics.TopicSpec(
            topic="wireless.audit",
            partitions=3,
            replicas=1,
            retention_ms=604800000,
            retention_bytes=21474836480,
        )

    def test_matching_topic_has_no_drift(self) -> None:
        live = reconcile_topics.LiveTopic(
            partitions=3,
            config={"retention.ms": "604800000", "retention.bytes": "21474836480"},
        )
        drift, planned = reconcile_topics.diff([self._spec()], FakeClient({"wireless.audit": live}))
        self.assertEqual([], drift)
        self.assertEqual({}, planned)

    def test_stale_values_are_reported(self) -> None:
        live = reconcile_topics.LiveTopic(
            partitions=3,
            config={"retention.ms": "2592000000", "retention.bytes": "-1"},
        )
        drift, planned = reconcile_topics.diff([self._spec()], FakeClient({"wireless.audit": live}))
        self.assertEqual(1, len(drift))
        self.assertEqual(
            {"retention.ms": "604800000", "retention.bytes": "21474836480"},
            planned["wireless.audit"],
        )

    def test_partition_drift_is_not_auto_applied(self) -> None:
        live = reconcile_topics.LiveTopic(
            partitions=24,
            config={"retention.ms": "604800000", "retention.bytes": "21474836480"},
        )
        drift, planned = reconcile_topics.diff([self._spec()], FakeClient({"wireless.audit": live}))
        self.assertEqual(1, len(drift))
        self.assertIn("partitions 24 != 3", str(drift[0]))
        self.assertEqual({}, planned)


class CommandLineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.manifest = self.root / "topics.manifest"
        self.manifest.write_text(
            "wireless.audit|3|1|604800000|21474836480\n", encoding="utf-8"
        )
        self.live = self.root / "live"
        self.writes = self.root / "writes"
        self._write_rpk()

    def _write_rpk(self) -> None:
        rpk = self.bin / "rpk"
        rpk.write_text(
            f"""#!/bin/sh
args="$*"
case "$args" in
  *"topic describe wireless.audit --print-summary"*)
    printf 'NAME PARTITIONS\\nwireless.audit 3\\n' ;;
  *"topic describe wireless.audit -c"*)
    printf 'KEY VALUE SOURCE\\n'
    printf 'retention.ms %s DYNAMIC_TOPIC_CONFIG\\n' "$(cat {self.live}.ms)"
    printf 'retention.bytes %s DYNAMIC_TOPIC_CONFIG\\n' "$(cat {self.live}.bytes)"
    ;;
  *"topic alter-config"*)
    printf '%s\\n' "$args" >> {self.writes}
    printf '%s\\n' "$args" | tr ' ' '\\n' | sed -n 's/^retention\\.ms=//p' > {self.live}.ms
    printf '%s\\n' "$args" | tr ' ' '\\n' | sed -n 's/^retention\\.bytes=//p' > {self.live}.bytes
    ;;
  *)
    printf 'unexpected rpk invocation: %s\\n' "$args" >&2
    exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        rpk.chmod(rpk.stat().st_mode | stat.S_IEXEC)
        (self.root / "live.ms").write_text("2592000000\n", encoding="utf-8")
        (self.root / "live.bytes").write_text("-1\n", encoding="utf-8")

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin}:{environment['PATH']}"
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), *arguments, "--manifest", str(self.manifest)],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_plan_reports_drift_without_writing(self) -> None:
        result = self._run("plan")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("drift wireless.audit", result.stdout)
        self.assertFalse(self.writes.exists())

    def test_check_fails_on_drift(self) -> None:
        self.assertEqual(2, self._run("check").returncode)

    def test_apply_requires_confirmation(self) -> None:
        result = self._run("apply")
        self.assertEqual(1, result.returncode)
        self.assertIn("refusing to apply", result.stderr)
        self.assertFalse(self.writes.exists())

    def test_apply_updates_and_verifies(self) -> None:
        result = self._run("apply", "--confirm", "APPLY-TOPIC-CONFIG")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("applied 1 topic setting(s)", result.stdout)
        self.assertEqual("604800000", (self.root / "live.ms").read_text().strip())
        self.assertEqual("21474836480", (self.root / "live.bytes").read_text().strip())
        self.assertIn("retention.ms=604800000", self.writes.read_text())

    def test_apply_is_a_no_op_when_clean(self) -> None:
        (self.root / "live.ms").write_text("604800000\n", encoding="utf-8")
        (self.root / "live.bytes").write_text("21474836480\n", encoding="utf-8")
        result = self._run("apply", "--confirm", "APPLY-TOPIC-CONFIG")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("topics match", result.stdout)
        self.assertFalse(self.writes.exists())


if __name__ == "__main__":
    unittest.main()
