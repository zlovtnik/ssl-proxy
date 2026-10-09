from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORIES = ("", "apps/integration-console", "apps/schema-migrator", "services/octopus", "apps/wg-key-rotator")

# Simulates only Docker's CLI boundary; no daemon, image pulls or pushes.
DOCKER = r'''
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
state_path = Path(os.environ["MOCK_STATE"])
state = json.loads(state_path.read_text())
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps({"args": args, "env": {k: os.getenv(k) for k in
        ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_CONTEXT")}}) + "\n")
if args[0] == "run":
    sys.stdin.buffer.read()
    labels = dict(args[i+1].split("=", 1) for i, x in enumerate(args) if x == "--label")
    state[args[args.index("--name")+1]] = labels
    state_path.write_text(json.dumps(state))
    if os.getenv("MOCK_WAIT"):
        Path(os.environ["MOCK_WAIT"]).touch()
        time.sleep(30)
    sys.exit(int(os.getenv("MOCK_RUN_STATUS", "0")))
if args[0] == "ps":
    filters = [args[i+1][6:].split("=", 1) for i, x in enumerate(args) if x == "--filter"]
    for name, labels in state.items():
        if all(labels.get(k) == v for k, v in filters):
            print(name)
if args[0] == "rm":
    for name in args[2:]:
        state.pop(name, None)
    state_path.write_text(json.dumps(state))
    sys.exit(int(os.getenv("MOCK_RM_STATUS", "0")))
if args[:2] == ["context", "inspect"]:
    sys.exit(int(os.getenv("MOCK_CONTEXT_STATUS", "0")))
if args[:2] == ["buildx", "prune"]:
    sys.exit(int(os.getenv("MOCK_PRUNE_STATUS", "0")))
'''


class JenkinsCiScriptsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        self.root.mkdir()
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.log = Path(self.temp.name) / "docker.jsonl"
        self.state = Path(self.temp.name) / "state.json"
        self.state.write_text("{}")
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "MOCK_STATE": str(self.state), "MOCK_LOG": str(self.log),
            "JOB_NAME": "test/main", "BUILD_NUMBER": "12", "WORKSPACE": str(self.root),
            "DOCKER_CONTEXT_NAME": "test-context", "BUILDER": "test-builder",
            "DOCKER_HOST": "tcp://docker.example:2376", "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "/certs/client", "CI_USE_DOCKER_CONTEXT": "false",
            "SUBMODULE_CI_READY": "false", "BRANCH_NAME": "main",
            "CI_REGISTRY": "registry.example:5000",
        }
        self.executable("docker", DOCKER)
        self.executable("cat", "print('2048')\n")
        self.executable("git", "print('a' * 40)\n")
        self.copy_scripts("")

    def executable(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n{body}")
        path.chmod(0o755)

    def copy_scripts(self, repository: str) -> None:
        target = self.root / "scripts/ci"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(ROOT / repository / "scripts/ci", target)

    def run_script(self, script: str, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", f"scripts/ci/{script}.sh"], cwd=self.root,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def calls(self) -> list[dict]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def shell(self, command: str, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-c", command], cwd=self.root,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def test_stage_cleanup_preserves_failure_and_other_stages(self) -> None:
        scope = self.shell('source scripts/ci/common.sh; printf "%s" "$CI_SCOPE"').stdout
        unrelated = {
            "other-stage": {"org.ssl-proxy.ci.run": scope, "org.ssl-proxy.ci.stage": "stats-reader"},
            "other-build": {"org.ssl-proxy.ci.run": "another-build", "org.ssl-proxy.ci.stage": "platform-sync"},
        }
        self.state.write_text(json.dumps(unrelated))
        result = self.run_script("platform-sync", SHOULD_RUN_PLATFORM_SYNC="true", MOCK_RUN_STATUS="17", MOCK_RM_STATUS="9")
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual(unrelated, json.loads(self.state.read_text()))

    def test_exit_cleanup_runs_after_success(self) -> None:
        result = self.run_script("platform-sync", SHOULD_RUN_PLATFORM_SYNC="true")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual({}, json.loads(self.state.read_text()))
        self.assertTrue(any(call["args"][0] == "rm" for call in self.calls()))

    def test_tar_failure_fails_stage_even_if_docker_succeeds(self) -> None:
        self.executable("tar", "import sys\nsys.exit(23)\n")
        result = self.run_script("platform-sync", SHOULD_RUN_PLATFORM_SYNC="true")
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertEqual({}, json.loads(self.state.read_text()))

    def test_termination_cleans_running_container(self) -> None:
        ready = self.root / "ready"
        process = subprocess.Popen(["bash", "scripts/ci/platform-sync.sh"], cwd=self.root,
                                   env={**self.env, "SHOULD_RUN_PLATFORM_SYNC": "true", "MOCK_WAIT": str(ready)},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "container did not start")
            os.killpg(process.pid, signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(143, process.returncode, stderr.decode())
            self.assertEqual({}, json.loads(self.state.read_text()))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()

    def test_final_cleanup_is_build_scoped_and_prune_failure_is_nonfatal(self) -> None:
        scope = self.shell('source scripts/ci/common.sh; printf "%s" "$CI_SCOPE"').stdout
        self.state.write_text(json.dumps({
            "aborted-stage": {"org.ssl-proxy.ci.run": scope, "org.ssl-proxy.ci.stage": "sensor"},
            "other-build": {"org.ssl-proxy.ci.run": "another-build"},
        }))
        result = self.run_script("cleanup", MOCK_PRUNE_STATUS="9")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual({"other-build": {"org.ssl-proxy.ci.run": "another-build"}}, json.loads(self.state.read_text()))
        prune = [call["args"] for call in self.calls() if call["args"][:2] == ["buildx", "prune"]]
        self.assertEqual([["buildx", "prune", "--builder", "test-builder", "--filter", "until=168h", "--reserved-space", "20GB", "--force"]], prune)

    def test_absent_context_skips_cache_prune(self) -> None:
        result = self.run_script("cleanup", MOCK_CONTEXT_STATUS="1")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(any(call["args"][:2] == ["buildx", "prune"] for call in self.calls()))

    def test_tls_refresh_and_pgvector_pull_use_explicit_context(self) -> None:
        result = self.run_script("docker-preflight", SHOULD_RUN_OCTOPUS="true", SHOULD_RUN_SCHEMA_MIGRATOR="false")
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.calls()
        self.assertEqual(["context", "inspect", "test-context"], calls[0]["args"])
        self.assertEqual(["context", "rm", "--force", "test-context"], calls[1]["args"])
        self.assertEqual(["context", "create", "test-context", "--docker",
                          "host=tcp://docker.example:2376,ca=/certs/client/ca.pem,cert=/certs/client/cert.pem,key=/certs/client/key.pem"], calls[2]["args"])
        self.assertEqual(["version"], calls[3]["args"])
        self.assertEqual(["pull", "pgvector/pgvector:pg16"], calls[4]["args"])
        for call in calls[3:]:
            self.assertEqual({"DOCKER_CONTEXT": "test-context", "DOCKER_HOST": None,
                              "DOCKER_CERT_PATH": None, "DOCKER_TLS_VERIFY": None}, call["env"])

    def test_inotify_rejection_precedes_any_docker_calls(self) -> None:
        for value in ("512", "invalid", ""):
            with self.subTest(value=value):
                self.executable("cat", f"print({value!r})\n")
                result = self.run_script("docker-preflight")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("--force-recreate jenkins-docker", result.stderr)
                self.assertEqual([], self.calls())

    def test_registry_drift_fails_before_docker(self) -> None:
        (self.root / "scripts/image_contract.py").write_text("print('registry.example:5000')\n")
        for registry in ("", "wrong.example:5000"):
            result = self.run_script("registry-check", CI_REGISTRY=registry)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("controller environment drift", result.stderr)
            self.assertEqual([], self.calls())
        self.assertEqual(0, self.run_script("registry-check").returncode)

    def test_change_flags_and_delegation_skip_container_tests(self) -> None:
        for script, flag in (("platform-sync", "PLATFORM_SYNC"), ("stats-reader", "STATS_READER"),
                             ("atheros-search", "ATHEROS_SEARCH"), ("schema-migrator", "SCHEMA_MIGRATOR"),
                             ("octopus", "OCTOPUS"), ("sensor", "SENSOR"),
                             ("atheros-search-contracts", "ATHEROS_SEARCH_CONTRACTS")):
            with self.subTest(script=script):
                result = self.run_script(script, **{f"SHOULD_RUN_{flag}": "false"})
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertFalse(any(call["args"][0] == "run" for call in self.calls()))
                if script in ("atheros-search", "schema-migrator", "octopus"):
                    result = self.run_script(script, SUBMODULE_CI_READY="true", **{f"SHOULD_RUN_{flag}": "true"})
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertFalse(any(call["args"][0] == "run" for call in self.calls()))

    def test_standalone_publication_keeps_full_sha_tags_and_metadata(self) -> None:
        for repository, images in (
            ("apps/integration-console", ("atheros-search", "atheros-search-ui")),
            ("apps/schema-migrator", ("schema-migrator-backend", "schema-migrator-ui")),
            ("apps/wg-key-rotator", ("wg-key-rotator",)),
        ):
            with self.subTest(repository=repository):
                self.copy_scripts(repository)
                (self.root / "atheros-search").mkdir(exist_ok=True)
                self.log.unlink(missing_ok=True)
                result = self.run_script("publish")
                self.assertEqual(0, result.returncode, result.stderr)
                builds = [c["args"] for c in self.calls() if c["args"][:2] == ["buildx", "build"]]
                self.assertEqual(len(images), len(builds))
                for image, args in zip(images, builds):
                    self.assertIn(f"registry.example:5000/{image}:{'a' * 40}", args)
                    self.assertIn(f"artifacts/{image}.json", args)
                    self.assertIn("--push", args)
                    self.assertIn("linux/amd64", args)
                self.assertFalse((self.root / "artifacts/build-context").exists())

    def test_standalone_publish_rejects_other_branches_and_empty_registry(self) -> None:
        for repository in ("apps/integration-console", "apps/schema-migrator", "apps/wg-key-rotator"):
            self.copy_scripts(repository)
            for env in ({"BRANCH_NAME": "feature/test"}, {"CI_REGISTRY": ""}):
                result = self.run_script("publish", **env)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], self.calls())

    def test_coverage_copies_complete_before_container_removal(self) -> None:
        for repository, script, env, expected_copies in (
            ("", "octopus", {"SHOULD_RUN_OCTOPUS": "true"}, 2),
            ("services/octopus", "test", {}, 3),
        ):
            self.copy_scripts(repository)
            self.log.unlink(missing_ok=True)
            result = self.run_script(script, **env)
            self.assertEqual(0, result.returncode, result.stderr)
            calls = [call["args"] for call in self.calls()]
            copies = [i for i, args in enumerate(calls) if args[0] == "cp"]
            self.assertEqual(expected_copies, len(copies))
            removal = next(i for i, args in enumerate(calls) if args[0] == "rm")
            self.assertLess(max(copies), removal)

    def test_script_syntax_and_independent_repository_helpers(self) -> None:
        common = (ROOT / "scripts/ci/common.sh").read_bytes()
        cleanup = (ROOT / "scripts/ci/cleanup.sh").read_bytes()
        for repository in REPOSITORIES:
            ci = ROOT / repository / "scripts/ci"
            self.assertEqual(common, (ci / "common.sh").read_bytes())
            self.assertEqual(cleanup, (ci / "cleanup.sh").read_bytes())
            for script in ci.rglob("*.sh"):
                result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr)
            pipeline = (ROOT / repository / "Jenkinsfile").read_text()
            self.assertNotIn("'''", pipeline)
            self.assertIn("timeout(time: 5, unit: 'MINUTES')", pipeline)
            self.assertIn("disableConcurrentBuilds(abortPrevious: true)", pipeline)


if __name__ == "__main__":
    unittest.main()
