from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "k8s/postgres-schema-executor/entrypoint.sh"


class PostgresSchemaExecutorTest(unittest.TestCase):
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
