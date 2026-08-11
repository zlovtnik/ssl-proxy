from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class MakeBuildxReadyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "builder.exists"
        self.log = self.root / "docker.log"
        docker = self.bin / "docker"
        docker.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_DOCKER_LOG\"\n"
            "if [ \"$1\" = info ]; then exit 0; fi\n"
            "if [ \"$1\" = buildx ] && [ \"$2\" = inspect ]; then\n"
            "  if [ -f \"$FAKE_BUILDER_STATE\" ]; then exit 0; fi\n"
            "  exit 1\n"
            "fi\n"
            "if [ \"$1\" = buildx ] && [ \"$2\" = create ]; then\n"
            "  touch \"$FAKE_BUILDER_STATE\"\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_make(self, plain_http: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ | {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "TMPDIR": str(self.root),
            "FAKE_BUILDER_STATE": str(self.state),
            "FAKE_DOCKER_LOG": str(self.log),
        }
        return subprocess.run(
            [
                "make",
                "-f",
                str(REPOSITORY_ROOT / "Makefile"),
                "buildx-ready",
                "REGISTRY=registry.test:5000/team",
                f"REGISTRY_PLAIN_HTTP={plain_http}",
                "BUILDER=test-publisher",
            ],
            cwd=self.root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_reuses_verified_http_builder_and_rejects_mode_mismatch(self) -> None:
        first = self.run_make("1")
        second = self.run_make("1")
        mismatch = self.run_make("0")

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertNotEqual(0, mismatch.returncode)
        self.assertIn("Use an unused dedicated builder", mismatch.stderr)
        self.assertEqual(1, self.log.read_text(encoding="utf-8").count("buildx create"))
        self.assertEqual(
            "registry.test:5000\n1\n",
            (self.root / "ssl-proxy-buildkitd-test-publisher.mode").read_text(
                encoding="utf-8"
            ),
        )

    def test_rejects_unverified_existing_builder_for_http(self) -> None:
        self.state.touch()

        result = self.run_make("1")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("dedicated HTTP-configured builder", result.stderr)
        self.assertNotIn("buildx create", self.log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
