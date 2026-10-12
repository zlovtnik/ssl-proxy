"""DQ retention and optional declarative broker properties."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class DQTopicTests(unittest.TestCase):
    def test_environment_topic_contract(self):
        config = next(
            doc for doc in yaml.safe_load_all(
                (ROOT / "cyber-stack/base/platform-config/configmap.yaml").read_text()
            ) if doc["metadata"]["name"] == "ssl-proxy-topics-manifest"
        )["data"]
        expected = {
            "dq.commands.v1": 7, "dq.worker-reports.v1": 7,
            "dq.events.v1": 30, "dq.dlq.v1": 30,
            "dq.registry.v1": 30, "dq.audit.v1": 180,
        }
        for content in (config["topics.manifest"], (ROOT / "docker/redpanda/topics.manifest").read_text()):
            actual = {}
            for line in content.splitlines():
                if line.startswith("dq."):
                    topic, partitions, replicas, retention, budget = line.split("|")
                    self.assertGreater(int(partitions), 0)
                    self.assertGreater(int(replicas), 0)
                    self.assertGreater(int(budget), 0)
                    actual[topic] = int(retention) // 86400000
            self.assertEqual(expected, actual)
        self.assertEqual(config["topics.properties"].strip(), (ROOT / "docker/redpanda/topics.properties").read_text().strip())
        self.assertIn("dq.registry.v1|cleanup.policy|compact", config["topics.properties"])
        for topic in expected:
            self.assertIn(f"{topic}|max.message.bytes|65536", config["topics.properties"])

    def test_bootstrap_applies_properties_and_rejects_unknown_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            log = base / "calls"
            rpk = base / "rpk"
            rpk.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DQ_TEST_CALLS\"\ncase \"$*\" in *--print-summary*) printf 'PARTITIONS 1\\n';; esac\n")
            rpk.chmod(0o755)
            curl = base / "curl"
            curl.write_text("#!/bin/sh\ncat >/dev/null\n")
            curl.chmod(0o755)
            manifest = base / "topics.manifest"
            manifest.write_text("dq.registry.v1|1|1|2592000000|134217728")
            properties = base / "topics.properties"
            environment = {
                **os.environ, "PATH": f"{base}:{os.environ['PATH']}",
                "DQ_TEST_CALLS": str(log), "SYNC_REDPANDA_TOPIC_MANIFEST": str(manifest),
                "SYNC_REDPANDA_TOPIC_PROPERTIES": str(properties),
            }
            properties.write_text("dq.registry.v1|cleanup.policy|compact")
            command = ["sh", str(ROOT / "docker/redpanda/bootstrap.sh")]
            result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--set cleanup.policy=compact", log.read_text())
            properties.write_text("dq.registry.v1|unapproved.property|value\n")
            result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
