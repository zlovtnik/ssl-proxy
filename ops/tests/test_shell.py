import io
import subprocess
import sys
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
        with (
            patch("subprocess.run", return_value=completed),
            self.assertRaises(shell.ShellCommandError) as raised,
        ):
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

    def test_current_context_wrappers_do_not_add_a_context_flag(self):
        completed = subprocess.CompletedProcess(args=["kubectl"], returncode=0)
        with patch("subprocess.run", return_value=completed) as mocked:
            shell.kubectl("get", "pods", context="")
            shell.helm("list", context="")

        commands = [call.args[0] for call in mocked.call_args_list]
        self.assertEqual(commands[0], ("kubectl", "get", "pods"))
        self.assertEqual(commands[1], ("helm", "list"))

    def test_kustomize_apply_uses_server_side_field_manager(self):
        completed = subprocess.CompletedProcess(args=["kubectl"], returncode=0)
        with patch("subprocess.run", return_value=completed) as mocked:
            shell.kustomize_apply("/tmp/overlay", context="test")

        command = mocked.call_args.args[0]
        self.assertEqual(
            command,
            (
                "kubectl",
                "--context",
                "test",
                "apply",
                "--server-side",
                "--field-manager=sslproxy-ops",
                "-k",
                "/tmp/overlay",
            ),
        )

    def test_stream_outputs_lines_in_real_time(self):
        result = shell.run(
            ["printf", "hello\nworld\n"],
            check=True,
            stream=True,
            cwd=Path("/tmp"),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)
        self.assertIn("world", result.stdout)

    def test_stream_and_capture_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            shell.run(["echo", "x"], capture=True, stream=True, cwd=Path("/tmp"))

    def test_stream_stderr_is_collected_and_printed(self):
        result = shell.run(
            ["sh", "-c", 'echo "err-output" >&2; echo "std-output"'],
            check=True,
            stream=True,
            cwd=Path("/tmp"),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("std-output", result.stdout)
        self.assertIn("err-output", result.stderr)

    def test_stream_raises_on_failure(self):
        with self.assertRaises(shell.ShellCommandError):
            shell.run(["false"], check=True, stream=True, cwd=Path("/tmp"))


if __name__ == "__main__":
    unittest.main()
