from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "k8s/postgres-schema-executor/entrypoint.sh"


class PostgresSchemaExecutorTest(unittest.TestCase):
    def test_manifest_files_are_applied_once_through_the_migration_ledger(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("apply_tracked_file()", script)
        self.assertIn("schema_migrator.state_schema_migrations", script)
        self.assertIn("pg_advisory_xact_lock", script)
        self.assertIn("migration_checksum_mismatch", script)
        self.assertIn("migration_already_applied", script)
        self.assertIn("migration applied: :migration_key", script)
        self.assertNotIn('psql_run --file="${sql_file}"', script)

    def test_pre_ledger_attestations_require_an_explicit_trusted_baseline(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("baseline_domain_ledger()", script)
        self.assertIn("legacy-manifest-attestation", script)
        self.assertIn('baselines/${attested_checksum}.sha256', script)
        self.assertIn("refusing to replay historical schema files", script)

    def test_ownership_drift_fails_before_migration(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("assert_domain_ownership()", script)
        self.assertIn("relation.relowner", script)
        self.assertIn("schema ownership drift detected before migration", script)
        self.assertIn('assert_domain_ownership "${domain}" true', script)
        self.assertNotIn("OWNER TO", script)

    def test_attested_domains_still_verify_every_manifest_table(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("domain_required_objects_exist()", script)
        self.assertIn("SELECT to_regclass('${object}') IS NOT NULL", script)
        self.assertIn('domain_required_objects_exist "${domain}" || exit 1', script)

    def test_role_defaults_are_checked_before_privileged_alter(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("FROM pg_db_role_setting setting", script)
        self.assertIn("'${expected_setting}' = ANY(setting.setconfig)", script)
        self.assertIn(
            'if role_search_path_is_current "${account}" "${expected_search_path}"; then',
            script,
        )
        self.assertNotIn('psql_run --set=ON_ERROR_STOP=1 <<SQL', script)

        expected_calls = (
            'ensure_role_search_path "${octopus_account}" "octopus_core, atheros_search"',
            'ensure_role_search_path "${search_account}" "atheros_search"',
            'ensure_role_search_path "${migrator_account}" "schema_migrator"',
            'ensure_role_search_path "${keycloak_account}" "keycloak"',
        )
        for call in expected_calls:
            self.assertIn(call, script)


if __name__ == "__main__":
    unittest.main()
