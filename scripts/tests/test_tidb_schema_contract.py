from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "check-tidb-schema-contract.py"
SPEC = importlib.util.spec_from_file_location("check_tidb_schema_contract", SCRIPT)
assert SPEC and SPEC.loader
contract_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = contract_check
SPEC.loader.exec_module(contract_check)


class SchemaMigratorStateContractTest(unittest.TestCase):
    def validate(self, version: str, checksum: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.yaml"
            resource = root / "manifest.properties"
            manifest.write_text(
                "schema_version: 001\n"
                "manifest_sha256: 10abd5b1ef8462fe4f521e064fc16193e50dec2cf508db34a4b32a9acc59f703\n",
                encoding="utf-8",
            )
            resource.write_text(
                f"version={version}\nchecksum={checksum}\n", encoding="utf-8"
            )
            failures: list[str] = []
            contract_check.validate_schema_migrator_state_contract(
                manifest, resource, failures
            )
            return failures

    def test_accepts_matching_runtime_contract(self) -> None:
        self.assertEqual(
            [],
            self.validate(
                "001", "10abd5b1ef8462fe4f521e064fc16193e50dec2cf508db34a4b32a9acc59f703"
            ),
        )

    def test_rejects_runtime_version_mismatch(self) -> None:
        failures = self.validate(
            "002", "10abd5b1ef8462fe4f521e064fc16193e50dec2cf508db34a4b32a9acc59f703"
        )
        self.assertEqual(1, len(failures))
        self.assertIn("version mismatch", failures[0])

    def test_rejects_runtime_checksum_mismatch(self) -> None:
        failures = self.validate("001", "0" * 64)
        self.assertEqual(1, len(failures))
        self.assertIn("checksum mismatch", failures[0])


if __name__ == "__main__":
    unittest.main()
