from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
EXECUTOR = REPO / "k8s/tidb-schema-executor/entrypoint.sh"
SCHEMA_MIGRATOR_MANIFEST = REPO / "sql/tidb/schema_migrator/manifest.yaml"


def manifest_value(name: str) -> str:
    match = re.search(
        rf"(?m)^{re.escape(name)}:\s*(\S+)\s*$",
        SCHEMA_MIGRATOR_MANIFEST.read_text(encoding="utf-8"),
    )
    if match is None:
        raise AssertionError(f"missing {name} in {SCHEMA_MIGRATOR_MANIFEST}")
    return match.group(1)


class TiDBSchemaExecutorTest(unittest.TestCase):
    def test_records_schema_migrator_manifest_after_grants_succeed(self) -> None:
        script = EXECUTOR.read_text(encoding="utf-8")
        version = manifest_value("schema_version")
        checksum = manifest_value("manifest_sha256")

        self.assertIn(
            'schema_migrator_manifest="${schema_root}/schema_migrator/manifest.yaml"',
            script,
        )
        self.assertIn(
            'schema_migrator_manifest_version="$(awk \'/^schema_version:/{ print $2; exit }\' "${schema_migrator_manifest}")"',
            script,
        )
        self.assertIn(
            'schema_migrator_manifest_sha="$(awk \'/^manifest_sha256:/{ print $2; exit }\' "${schema_migrator_manifest}")"',
            script,
        )
        self.assertIn(
            "INSERT INTO schema_migrator.state_schema_migrations "
            "(version, checksum, applied_at, applied_by)",
            script,
        )
        self.assertIn(
            "VALUES ('${schema_migrator_manifest_version}', "
            "'${schema_migrator_manifest_sha}', UTC_TIMESTAMP(6), "
            "'tidb-runtime-schema') ON DUPLICATE KEY UPDATE",
            script,
        )
        self.assertIn(
            "UPDATE schema_migrator.schema_readiness SET "
            "required_version='${schema_migrator_manifest_version}', "
            "applied_version='${schema_migrator_manifest_version}', "
            "required_checksum='${schema_migrator_manifest_sha}', "
            "applied_checksum='${schema_migrator_manifest_sha}', ready=1",
            script,
        )

        self.assertEqual("001", version)
        self.assertRegex(checksum, r"^[0-9a-f]{64}$")
        self.assertLess(
            script.index('apply_grant_fixture "${schema_root}/schema_migrator/grants/least_privilege.sql.tmpl"'),
            script.index("INSERT INTO schema_migrator.state_schema_migrations"),
        )
        self.assertLess(
            script.index("INSERT INTO schema_migrator.state_schema_migrations"),
            script.index("UPDATE schema_migrator.schema_readiness"),
        )

    def test_ssl_flags_are_conditional(self) -> None:
        script = EXECUTOR.read_text(encoding="utf-8")
        self.assertIn(
            'ca_file="${TIDB_TLS_CA_FILE:-}"',
            script,
        )
        self.assertIn('if [ -n "${ca_file}" ]', script)
        self.assertIn("--ssl-mode=VERIFY_IDENTITY --ssl-ca=${ca_file}", script)
        self.assertIn("--ssl-mode=DISABLED", script)


if __name__ == "__main__":
    unittest.main()
