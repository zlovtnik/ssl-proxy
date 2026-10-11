from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ColumnLimitsTest(unittest.TestCase):
    def check(self, columns: int, baseline: str = "") -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts/check-column-limits.sh"
            script.parent.mkdir()
            shutil.copyfile(ROOT / "scripts/check-column-limits.sh", script)
            config = root / "config/postgres-column-limits.txt"
            config.parent.mkdir()
            config.write_text(baseline)
            sql = root / "sql/postgres/example/01_tables/001_example.sql"
            sql.parent.mkdir(parents=True)
            definitions = ",\n".join(f"column_{number} text" for number in range(columns))
            sql.write_text(f"CREATE TABLE example.records (\n{definitions}\n);\n")
            return subprocess.run(["bash", str(script)], capture_output=True, text=True)

    def test_new_tables_must_obey_default_limit(self) -> None:
        self.assertEqual(0, self.check(15).returncode)
        result = self.check(16)
        self.assertEqual(1, result.returncode)
        self.assertIn("example.records has 16 columns, limit 15", result.stdout)

    def test_existing_table_cannot_grow_beyond_frozen_limit(self) -> None:
        self.assertEqual(0, self.check(16, "example.records 16\n").returncode)
        self.assertEqual(1, self.check(17, "example.records 16\n").returncode)

    def test_stale_or_invalid_limit_is_rejected(self) -> None:
        for baseline in ("example.missing 16\n", "example.records invalid\n",
                         "example.records 16\nexample.records 17\n"):
            with self.subTest(baseline=baseline):
                self.assertEqual(2, self.check(15, baseline).returncode)


if __name__ == "__main__":
    unittest.main()
