from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh"


class RedpandaMaintenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        self.trimmed = self.root / "trimmed"
        self._write_executable(
            "rpk",
            f"""#!/bin/sh
            printf '%s\n' "$*" >> {self.calls}
            if [ "$1 $2" = "topic describe" ]; then
              if [ -f {self.trimmed} ]; then
                cat <<'EOF'
PARTITION LEADER EPOCH REPLICAS LOG-START-OFFSET HIGH-WATERMARK
0 0 1 [0] 800 1000
1 0 1 [0] 800 1000
EOF
                exit 0
              fi
              cat <<'EOF'
PARTITION LEADER EPOCH REPLICAS LOG-START-OFFSET HIGH-WATERMARK
0 0 1 [0] 100 1000
1 0 1 [0] 100 1000
EOF
            elif [ "$1 $2" = "group list" ]; then
              cat <<'EOF'
BROKER GROUP STATE
0 octopus-scan-v1 Empty
EOF
              if [ "${{MOCK_AUDIT_GROUP:-0}}" = 1 ]; then
                printf '0 wireless-audit-postgres-v1 Empty\n'
              fi
            elif [ "$1 $2 $4" = "group describe -c" ]; then
              if [ "$3" = "wireless-audit-postgres-v1" ]; then
                cat <<'EOF'
TOPIC PARTITION CURRENT-OFFSET LOG-START-OFFSET LOG-END-OFFSET LAG
wireless.audit 0 900 100 1000 100
wireless.audit 1 900 100 1000 100
EOF
              else
                cat <<'EOF'
TOPIC PARTITION CURRENT-OFFSET LOG-START-OFFSET LOG-END-OFFSET LAG
sync.scan.request 0 900 100 1000 100
sync.scan.request 1 850 100 1000 150
EOF
              fi
            elif [ "$1 $2" = "topic consume" ]; then
              case "$*" in
                *%d*) printf '2000000\n' ;;
                *) printf '800\n' ;;
              esac
            elif [ "$1 $2" = "topic trim-prefix" ]; then
              touch {self.trimmed}
              exit 0
            else
              exit 2
            fi
            """,
        )
        self._write_executable(
            "psql",
            r"""#!/bin/sh
            case "$*" in
              *MIN\(observed_at\)*) printf '1000|9999999999\n' ;;
              *) printf '%s\n' "${EVIDENCE_COUNT:-699}" ;;
            esac
            """,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_executable(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def _run(
        self, topics: str, *, dry_run: str, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        topics_file = self.root / "topics.tsv"
        topics_file.write_text(textwrap.dedent(topics).lstrip(), encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "TOPICS_FILE": str(topics_file),
                "DRY_RUN": dry_run,
                "PUSHGATEWAY_URL": "",
                "MAX_TRIM_FRACTION": "0.90",
            }
        )
        environment.update(extra_env or {})
        return subprocess.run(
            ["bash", str(SCRIPT)],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_dry_run_uses_minimum_commit_and_cutoff(self) -> None:
        result = self._run(
            "sync.scan.request\t3\tnone\toctopus-scan-v1\t-\n",
            dry_run="true",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("octopus-scan-v1", result.stdout)
        self.assertIn("dry-run complete", result.stdout)
        self.assertNotIn("trim-prefix", self.calls.read_text(encoding="utf-8"))

    def test_one_blocked_topic_prevents_every_trim(self) -> None:
        result = self._run(
            """
            wireless.audit\t3\tpg\twireless-audit-postgres-v1\twireless-audit-postgres-v1
            sync.scan.request\t3\tnone\toctopus-scan-v1\t-
            """,
            dry_run="false",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("required group wireless-audit-postgres-v1", result.stderr)
        self.assertIn("no trim commands were run", result.stderr)
        self.assertNotIn("trim-prefix", self.calls.read_text(encoding="utf-8"))

    def test_apply_trims_from_plan_and_verifies_new_lso(self) -> None:
        result = self._run(
            "sync.scan.request\t3\tnone\toctopus-scan-v1\t-\n",
            dry_run="false",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("trim complete", result.stdout)
        self.assertIn("topic trim-prefix --from-file", self.calls.read_text(encoding="utf-8"))

    def test_incomplete_offset_evidence_blocks_postgres_topic(self) -> None:
        result = self._run(
            "wireless.audit\t3\tpg\twireless-audit-postgres-v1\twireless-audit-postgres-v1\n",
            dry_run="false",
            extra_env={"MOCK_AUDIT_GROUP": "1", "EVIDENCE_COUNT": "699"},
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("has 699/700 persisted offsets", result.stderr)
        self.assertNotIn("trim-prefix", self.calls.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
