from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "k8s/postgres-schema-executor/entrypoint.sh"


class PostgresSchemaExecutorTest(unittest.TestCase):
    def test_only_intact_attested_domains_are_not_reapplied(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn(
            'if domain_is_attested "${domain}" "${expected_version}" "${expected_manifest}" && domain_required_objects_exist "${domain}"; then',
            script,
        )
        self.assertIn('echo "schema domain already attested: ${domain}"', script)
        self.assertIn(
            'echo "schema domain attested but required objects are missing; reconciling: ${domain}" >&2',
            script,
        )
        self.assertIn("SELECT to_regclass('${domain}.schema_readiness') IS NOT NULL", script)
        self.assertIn("AND required_checksum = '${expected_manifest}'", script)
        self.assertIn("AND applied_checksum = '${expected_manifest}'", script)
        self.assertIn('applied_domains="${applied_domains} ${domain}"', script)
        self.assertIn('for domain in ${applied_domains}; do', script)
        self.assertIn('case "${domain}" in', script)

    def test_attested_domains_verify_every_manifest_table(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("domain_required_objects_exist()", script)
        self.assertIn(
            "grep -hioE 'CREATE TABLE IF NOT EXISTS [a-z_]+\\.[a-z0-9_]+'",
            script,
        )
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
