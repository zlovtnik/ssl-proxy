from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "ci/tasks/metrics-tsan-test.sh"


class MetricsTsanRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "calls.jsonl"
        self.env = {
            **os.environ, "PATH": f"{self.root}:{os.environ['PATH']}",
            "MOCK_LOG": str(self.log), "MOCK_OS": "Linux", "MOCK_ARCH": "x86_64",
            "MOCK_TEST_STATUS": "0", "MOCK_SETARCH_STATUS": "0",
        }
        self.executable("uname", '''
import os, sys
print(os.environ["MOCK_OS" if sys.argv[1] == "-s" else "MOCK_ARCH"])
''')
        self.executable("setarch", '''
import json, os, sys
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps(["setarch", *sys.argv[1:]]) + "\\n")
status = int(os.environ["MOCK_SETARCH_STATUS"])
if status:
    sys.exit(status)
os.execvp(sys.argv[3], sys.argv[3:])
''')
        self.executable("ctest", '''
import json, os, sys
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps(["ctest", *sys.argv[1:]]) + "\\n")
sys.exit(int(os.environ["MOCK_TEST_STATUS"]))
''')

    def executable(self, name: str, body: str) -> None:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n{body}")
        path.chmod(0o755)

    def run_tests(self, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(RUNNER), "/tmp/metrics build"],
                              env={**self.env, **env}, capture_output=True,
                              text=True, timeout=5)

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_linux_x86_uses_process_local_layout_and_quoted_path(self) -> None:
        result = self.run_tests()
        self.assertEqual(0, result.returncode, result.stderr)
        command = ["ctest", "--test-dir", "/tmp/metrics build", "--output-on-failure"]
        self.assertEqual([["setarch", "x86_64", "-R", *command], command], self.calls())

    def test_other_supported_platforms_run_ctest_directly(self) -> None:
        for os_name, architecture in (("Linux", "aarch64"), ("Darwin", "arm64")):
            with self.subTest(os_name=os_name, architecture=architecture):
                self.log.unlink(missing_ok=True)
                result = self.run_tests(MOCK_OS=os_name, MOCK_ARCH=architecture)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([["ctest", "--test-dir", "/tmp/metrics build",
                                   "--output-on-failure"]], self.calls())

    def test_race_and_test_failures_propagate_without_retry(self) -> None:
        result = self.run_tests(MOCK_TEST_STATUS="66")
        self.assertEqual(66, result.returncode, result.stderr)
        self.assertEqual(2, len(self.calls()))

    def test_denied_personality_fails_without_unsanitized_fallback(self) -> None:
        result = self.run_tests(MOCK_SETARCH_STATUS="1")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(1, len(self.calls()))


if __name__ == "__main__":
    unittest.main()
