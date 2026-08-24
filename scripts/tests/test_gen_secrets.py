from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "gen-secrets"


class GenSecretsLauncherTest(unittest.TestCase):
    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ("bash", "-n", str(SCRIPT)),
            cwd=REPOSITORY_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(0, result.returncode, result.stderr)

    def test_invalid_command_fails_before_secret_generation(self) -> None:
        result = subprocess.run(
            (str(SCRIPT), "not-a-command"),
            cwd=REPOSITORY_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(64, result.returncode)
        self.assertIn("Usage:", result.stderr)

    def test_launcher_uses_retained_elixir_rotator(self) -> None:
        content = SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("ops-python.sh", content)
        self.assertIn("apps/wg-key-rotator", content)
        self.assertIn("WgKeyRotator.CLI.main", content)
        self.assertTrue((REPOSITORY_ROOT / "apps" / "wg-key-rotator").is_dir())


if __name__ == "__main__":
    unittest.main()
