"""Exercise local topic provisioning against rpk's missing-topic behavior."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RedpandaBootstrapTests(unittest.TestCase):
    def test_local_heartbeat_consumer_source_and_dlq_are_provisioned(self):
        topics = {}
        for line in (ROOT / "docker/redpanda/topics.manifest").read_text().splitlines():
            if line and not line.startswith("#"):
                name, partitions, replicas, *_ = line.split("|")
                topics[name] = (int(partitions), int(replicas))

        # The local Octopus consumer gate enables heartbeat ingestion even when
        # OCTOPUS_ENABLED_PROCESSORS selects only the sync processor catalog.
        for topic in ("wireless.sensor.heartbeat", "wireless.sensor.heartbeat.dlq"):
            with self.subTest(topic=topic):
                self.assertIn(topic, topics)
                partitions, replicas = topics[topic]
                self.assertGreater(partitions, 0)
                self.assertEqual(replicas, 1)

    def run_bootstrap(self, summary, describe_status=0):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            calls = base / "calls"
            rpk = base / "rpk"
            rpk.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$TEST_CALLS"\n'
                'case "$*" in\n'
                '  *--print-summary*) printf "%s\\n" "$TEST_SUMMARY"; '
                'exit "$TEST_DESCRIBE_STATUS";;\n'
                "esac\n"
            )
            rpk.chmod(0o755)
            curl = base / "curl"
            curl.write_text("#!/bin/sh\ncat >/dev/null\n")
            curl.chmod(0o755)
            manifest = base / "topics.manifest"
            manifest.write_text("sync.scan.request|3|1|2592000000|536870912\n")
            result = subprocess.run(
                ["sh", str(ROOT / "docker/redpanda/bootstrap.sh")],
                env={
                    **os.environ,
                    "PATH": f"{base}:{os.environ['PATH']}",
                    "TEST_CALLS": str(calls),
                    "TEST_SUMMARY": summary,
                    "TEST_DESCRIBE_STATUS": str(describe_status),
                    "SYNC_REDPANDA_TOPIC_MANIFEST": str(manifest),
                    "SYNC_REDPANDA_TOPIC_PROPERTIES": str(base / "absent.properties"),
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result, calls.read_text()

    def test_missing_topic_with_successful_zero_partition_summary_is_created(self):
        result, calls = self.run_bootstrap("NAME sync.scan.request\nPARTITIONS 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("topic create sync.scan.request", calls)
        self.assertIn("--partitions 3 --replicas 1", calls)
        self.assertNotIn("add-partitions", calls)

    def test_failed_description_creates_topic(self):
        result, calls = self.run_bootstrap("", describe_status=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("topic create sync.scan.request", calls)

    def test_existing_topic_expands_by_missing_partitions(self):
        result, calls = self.run_bootstrap("NAME sync.scan.request\nPARTITIONS 1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("topic add-partitions sync.scan.request", calls)
        self.assertIn("--num 2", calls)
        self.assertNotIn("topic create", calls)

    def test_excess_existing_partitions_fail_closed(self):
        result, calls = self.run_bootstrap("PARTITIONS 4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("topic_partition_mismatch", result.stdout)
        self.assertNotIn("topic create", calls)
        self.assertNotIn("alter-config", calls)

    def test_invalid_partition_summary_fails_closed(self):
        for summary in ("", "PARTITIONS unknown", "PARTITIONS -1"):
            with self.subTest(summary=summary):
                result, calls = self.run_bootstrap(summary)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("topic_partition_parse_failed", result.stdout)
                self.assertNotIn("topic create", calls)
                self.assertNotIn("alter-config", calls)


if __name__ == "__main__":
    unittest.main()
