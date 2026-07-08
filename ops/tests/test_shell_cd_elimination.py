import unittest
from pathlib import Path

from sslproxy_ops.paths import repo_root


class ShellCdEliminationTest(unittest.TestCase):
    def test_src_does_not_call_os_chdir(self):
        src = repo_root() / "ops" / "src"
        offenders = [
            path
            for path in src.rglob("*.py")
            if "os.chdir" in path.read_text()
        ]

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

