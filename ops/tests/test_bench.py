import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import typer

from sslproxy_ops.commands.bench import wg_path


class BenchTest(unittest.TestCase):
    def test_wg_path_requires_at_least_one_target(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("shutil.which", return_value="/usr/bin/iperf3"):
                with self.assertRaises(typer.Exit) as raised:
                    wg_path(
                        duration=1,
                        parallel=1,
                        udp_bw="1M",
                        out_dir=Path(tmp_dir),
                        bypass_target="",
                        plain_target=" ",
                        obfs_target=None,
                        iperf_server=None,
                        perf_pid=None,
                    )

        self.assertEqual(raised.exception.exit_code, 2)


if __name__ == "__main__":
    unittest.main()
