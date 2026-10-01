"""Execute required Search database contracts using canonical DDL and runtime grants."""
import argparse
import hashlib
import json
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
REQUIRED = os.environ.get("ATHSEARCH_DB_REQUIRED") == "true"


class AtherosReportingTest(unittest.TestCase):
    def test_queries_against_canonical_schema(self):
        if DockerContainer is None:
            if REQUIRED:
                self.fail("required database contracts need scripts/requirements-test.txt")
            self.skipTest("install scripts/requirements-test.txt")
        with (DockerContainer("pgvector/pgvector:0.8.6-pg16-bookworm")
              .with_env("POSTGRES_PASSWORD", "contract-test")
              .with_env("POSTGRES_DB", "sync")
              .with_exposed_ports(5432)
              .waiting_for(LogMessageWaitStrategy("database system is ready to accept connections", times=2))) as postgres:
            def sql(statement):
                result = postgres.exec(["psql", "-X", "-U", "postgres", "-d", "sync",
                                        "-v", "ON_ERROR_STOP=1", "-c", statement])
                self.assertEqual(result.exit_code, 0, result.output.decode())

            sql("CREATE EXTENSION vector")
            manifests = {}
            for domain in ("octopus_core", "atheros_search"):
                schema = ROOT / "sql/postgres" / domain
                manifest = yaml.safe_load((schema / "manifest.yaml").read_text())
                checksum = hashlib.sha256()
                for relative in manifest["apply_order"]:
                    data = (schema / relative).read_bytes()
                    checksum.update(relative.encode() + b"\0" + data + b"\0")
                    sql(data.decode())
                self.assertEqual(checksum.hexdigest(), manifest["manifest_sha256"])
                manifests[domain] = manifest
                version, sha = manifest["schema_version"], manifest["manifest_sha256"]
                sql(f"UPDATE {domain}.schema_readiness SET required_version='{version}', "
                    f"applied_version='{version}', required_checksum='{sha}', "
                    f"applied_checksum='{sha}', ready=true")

            sql("CREATE ROLE octopus_contract LOGIN PASSWORD 'contract-test'; "
                "CREATE ROLE athsearch_contract LOGIN PASSWORD 'contract-test'; "
                "ALTER ROLE athsearch_contract SET search_path=atheros_search,public; "
                "ALTER ROLE athsearch_contract SET timezone='UTC'; "
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            for domain in manifests:
                template = (ROOT / "sql/postgres" / domain / "grants/least_privilege.sql.tmpl").read_text()
                sql(template.replace("{{OCTOPUS_ACCOUNT}}", "octopus_contract")
                    .replace("{{ATHEROS_SEARCH_ACCOUNT}}", "athsearch_contract"))

            endpoint = f"{postgres.get_container_host_ip()}:{postgres.get_exposed_port(5432)}/sync?sslmode=disable"
            env = dict(os.environ,
                       ATHSEARCH_PROVISION_TEST_DSN=f"postgres://postgres:contract-test@{endpoint}",
                       ATHSEARCH_REPORT_TEST_DSN=f"postgres://athsearch_contract:contract-test@{endpoint}",
                       ATHSEARCH_TEST_MANIFEST_SHA256=manifests["atheros_search"]["manifest_sha256"])
            packages = [f"./internal/{name}" for name in
                        ("search", "reporting", "worker", "db", "etlhealth", "assets", "savedviews", "app/repair")]
            result = subprocess.run(["go", "test", "-json", "-p=1", "-tags=dbcontract", "-count=1",
                                     "-run", "TestReporting|TestDatabase", *packages],
                                    cwd=ROOT / "apps/integration-console/atheros-search", env=env,
                                    text=True, capture_output=True, timeout=300)
            print(result.stdout)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
            self.assertFalse([event for event in events if event["Action"] == "skip"], "required database tests skipped")
            tested = {event["Package"].split("/internal/")[-1] for event in events
                      if event["Action"] == "pass" and "Test" in event}
            self.assertEqual(tested, {package.removeprefix("./internal/") for package in packages},
                             "every database consumer must execute a test")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--required", action="store_true", help="fail instead of skipping unavailable dependencies")
    args, remaining = parser.parse_known_args()
    REQUIRED = REQUIRED or args.required
    unittest.main(argv=[__file__, *remaining])
