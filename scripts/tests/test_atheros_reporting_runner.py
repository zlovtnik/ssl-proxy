"""Check database-contract runner diagnostics without starting PostgreSQL."""

import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import test_atheros_reporting


class AtherosReportingRunnerTest(unittest.TestCase):
    def run_contracts(self, **kwargs):
        return test_atheros_reporting.AtherosReportingTest().run_go_tests(
            ["./internal/search"], pattern="TestReporting|TestDatabase",
            timeout=300, test_timeout="2m", **kwargs)

    def test_timeout_preserves_partial_output(self):
        for output in (b'{"Action":"run","Test":"TestDatabase"}',
                       '{"Action":"run","Test":"TestDatabase"}'):
            with self.subTest(output=output), patch("test_atheros_reporting.subprocess.run") as run:
                run.side_effect = subprocess.TimeoutExpired(
                    ["go", "test"], 300, output=output, stderr=b"compiler diagnostics")
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(
                        AssertionError, "timed out after 300s"):
                    self.run_contracts()
                self.assertIn('"Test":"TestDatabase"', captured.getvalue())
                self.assertIn("compiler diagnostics", captured.getvalue())

    def test_failure_preserves_build_diagnostics(self):
        with patch("test_atheros_reporting.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["go", "test"], 1, stdout="build failed", stderr="undefined symbol")
            captured = io.StringIO()
            with redirect_stdout(captured), self.assertRaisesRegex(AssertionError, "undefined symbol"):
                self.run_contracts()
            self.assertIn("build failed", captured.getvalue())
            self.assertIn("undefined symbol", captured.getvalue())

    def test_runtime_environment_and_serial_execution_are_preserved(self):
        env = {"ATHSEARCH_REPORT_TEST_DSN": "contract-test"}
        with patch("test_atheros_reporting.subprocess.run") as run, redirect_stdout(io.StringIO()):
            run.return_value = subprocess.CompletedProcess(["go", "test"], 0, stdout="", stderr="")
            self.run_contracts(env=env)
        self.assertIs(run.call_args.kwargs["env"], env)
        self.assertIn("-p=1", run.call_args.args[0])
        self.assertIn("-timeout=2m", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["timeout"], 300)


if __name__ == "__main__":
    unittest.main()
