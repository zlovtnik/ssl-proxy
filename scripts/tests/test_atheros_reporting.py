"""Run reporting query regressions on canonical DDL in a fresh Testcontainer."""
import os
import subprocess
import unittest
from pathlib import Path

import yaml

try:
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy
except ImportError:
    DockerContainer = None

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipIf(DockerContainer is None, "install scripts/requirements-test.txt")
class AtherosReportingTest(unittest.TestCase):
    def test_queries_against_canonical_schema(self):
        with (DockerContainer("pgvector/pgvector:0.8.6-pg16-bookworm")
              .with_env("POSTGRES_PASSWORD", "report-test")
              .with_env("POSTGRES_DB", "report_test")
              .with_exposed_ports(5432)
              .waiting_for(LogMessageWaitStrategy("database system is ready to accept connections", times=2))) as postgres:
            schema = ROOT / "sql/postgres/atheros_search"
            result = postgres.exec(["psql", "-X", "-U", "postgres", "-d", "report_test", "-c", "CREATE EXTENSION vector"])
            self.assertEqual(result.exit_code, 0, result.output.decode())
            manifest = yaml.safe_load((schema / "manifest.yaml").read_text())
            for relative in manifest["apply_order"]:
                result = postgres.exec(["psql", "-X", "-U", "postgres", "-d", "report_test",
                                        "-v", "ON_ERROR_STOP=1", "-c", (schema / relative).read_text()])
                self.assertEqual(result.exit_code, 0, result.output.decode())
            env = dict(os.environ, ATHSEARCH_REPORT_TEST_DSN=(
                f"postgres://postgres:report-test@{postgres.get_container_host_ip()}:"
                f"{postgres.get_exposed_port(5432)}/report_test?sslmode=disable"))
            result = subprocess.run(["go", "test", "./internal/search", "-run", "TestReporting", "-v", "-count=1"],
                                    cwd=ROOT / "apps/integration-console/atheros-search", env=env,
                                    text=True, capture_output=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout)
