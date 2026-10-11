from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class OctopusTopicStartupTest(unittest.TestCase):
    def test_gate_waits_for_broker_and_all_topic_dimensions(self) -> None:
        document = next(yaml.safe_load_all((ROOT / "cyber-stack/base/java-coordinator/deployment.yaml").read_text()))
        gate = document["spec"]["template"]["spec"]["initContainers"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "topics.manifest"
            manifest.write_text("# topic|partitions|replicas|retention.ms|retention.bytes\nfirst|24|1|1000|1024\nheartbeat|3|1|1000|1024\n")
            rpk = root / "rpk"
            rpk.write_text("""#!/bin/sh
set -eu
[ "$1 $2" = 'topic list' ]
count=0
[ ! -f "$TMPDIR/polls" ] || count=$(cat "$TMPDIR/polls")
count=$((count + 1))
printf '%s' "$count" >"$TMPDIR/polls"
[ "$count" -gt 1 ] || exit 1
printf 'NAME PARTITIONS REPLICAS\\nfirst 24 1\\n'
case "$count" in
  2) ;;
  3) printf 'heartbeat 1 1\\n' ;;
  4) printf 'heartbeat 3 2\\n' ;;
  *) printf 'heartbeat 3 1\\n' ;;
esac
""")
            rpk.chmod(0o755)
            sleep = root / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n")
            sleep.chmod(0o755)
            script = gate["args"][0].replace("/app/docker/redpanda/topics.manifest", str(manifest))
            result = subprocess.run(gate["command"] + [script], env={**os.environ,
                "PATH": f"{root}:{os.environ['PATH']}", "TMPDIR": str(root),
                "SYNC_REDPANDA_BOOTSTRAP_SERVERS": "broker:9092"},
                capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("5", (root / "polls").read_text())
            self.assertIn("Declared Redpanda topics are available", result.stdout)


if __name__ == "__main__":
    unittest.main()
