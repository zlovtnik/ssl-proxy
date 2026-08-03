import unittest
from unittest.mock import patch

from sslproxy_ops.commands.pipeline import run_allow_fail


class PipelineTest(unittest.TestCase):
    @patch("sslproxy_ops.commands.pipeline.shell.run")
    def test_status_diagnostics_are_non_fatal(self, run):
        command = ["rpk", "cluster", "info"]

        run_allow_fail(command)

        run.assert_called_once_with(command, check=False, capture=False)


if __name__ == "__main__":
    unittest.main()
