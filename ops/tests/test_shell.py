import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from sslproxy_ops import shell
from sslproxy_ops.paths import repo_root


class ShellTest(unittest.TestCase):
    def test_run_raises_typed_error(self):
        completed = subprocess.CompletedProcess(
            args=["false"],
            returncode=7,
            stdout="",
            stderr="boom",
        )
        with patch("subprocess.run", return_value=completed):
            with self.assertRaises(shell.ShellCommandError) as raised:
                shell.run(["false"], cwd=Path("/tmp"), capture=True)

        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(raised.exception.stderr, "boom")

    def test_compose_passes_repo_cwd_by_default(self):
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=completed) as mocked:
            shell.compose("ps", capture=True)

        args, kwargs = mocked.call_args
        self.assertEqual(args[0], ("docker", "compose", "ps"))
        self.assertEqual(kwargs["cwd"], repo_root())


if __name__ == "__main__":
    unittest.main()
