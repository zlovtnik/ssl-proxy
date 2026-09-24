from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def write_stub(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class StubEnvironment:
    """Temporary bin directory of stub commands plus a shared call log."""

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="storage-ops-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"

    def close(self) -> None:
        self.directory.cleanup()

    def stub(self, name: str, body: str) -> None:
        write_stub(self.bin, name, body)

    def environment(self, **extra: str) -> dict[str, str]:
        return os.environ | {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STUB_LOG": str(self.log),
        } | extra

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()


class AuditScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = StubEnvironment()
        self.addCleanup(self.env.close)
        self.output = self.env.root / "snapshots"
        self.env.stub(
            "docker",
            "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\n"
            "if [ \"${1:-}\" = ps ]; then printf '%s\\n' 'ssl-proxy-platform-postgres'; fi\n",
        )
        self.env.stub("rpk", "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\n")
        self.env.stub("kubectl", "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\nexit 1\n")
        self.env.stub("k3s", "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\nexit 1\n")
        self.env.stub("journalctl", "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\nexit 1\n")
        self.env.stub("sudo", "exit 1\n")

    def run_audit(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(REPOSITORY_ROOT / "ops" / "disk" / "audit.sh"), *arguments],
            cwd=REPOSITORY_ROOT,
            env=self.env.environment(AUDIT_OUTPUT_DIR=str(self.output)),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_writes_snapshot_with_all_sections(self) -> None:
        result = self.run_audit("unittest")
        self.assertEqual(result.returncode, 0, result.stdout)
        snapshots = list(self.output.glob("*.txt"))
        self.assertEqual(len(snapshots), 1, snapshots)
        content = snapshots[0].read_text(encoding="utf-8")
        for section in (
            "===== filesystems =====",
            "===== host paths (du) =====",
            "===== container runtime images and containers =====",
            "===== redpanda topic sizes =====",
            "===== consumer groups on capped topics =====",
            "===== postgres relation sizes =====",
            "===== logs =====",
        ):
            self.assertIn(section, content)
        self.assertIn("label=unittest", content)
        self.assertRegex(
            snapshots[0].name, r"^\d{4}-\d{2}-\d{2}-unittest\.txt$"
        )

    def test_unreadable_paths_degrade_instead_of_failing(self) -> None:
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout)
        content = next(self.output.glob("*.txt")).read_text(encoding="utf-8")
        self.assertTrue(
            "absent:" in content or "skipped:" in content,
            content,
        )

    def test_label_is_sanitized_for_the_output_path(self) -> None:
        result = self.run_audit("../../escape")
        self.assertEqual(result.returncode, 0, result.stdout)
        snapshots = list(self.output.glob("*.txt"))
        self.assertEqual(len(snapshots), 1, snapshots)
        self.assertNotIn("/", snapshots[0].name)
        self.assertRegex(
            snapshots[0].name, r"^\d{4}-\d{2}-\d{2}-[A-Za-z0-9._-]+\.txt$"
        )

    def test_only_read_only_commands_are_invoked(self) -> None:
        self.run_audit("readonly")
        forbidden = ("apply", "delete", "patch", "replace", "prune", "set ")
        for line in self.env.calls():
            for verb in forbidden:
                self.assertNotIn(verb, line, line)


class CheckTopicsScriptTest(unittest.TestCase):
    def run_check(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(REPOSITORY_ROOT / "ops" / "redpanda" / "check-topics.sh"), *arguments],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_static_check_passes(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("static manifest contract holds", result.stdout)

    def test_unknown_argument_fails(self) -> None:
        result = self.run_check("--nonsense")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("unknown argument", result.stdout)

    def test_help_exits_zero(self) -> None:
        result = self.run_check("--help")
        self.assertEqual(result.returncode, 0, result.stdout)


class RegistryGcScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = StubEnvironment()
        self.addCleanup(self.env.close)
        self.env.stub(
            "make",
            "printf '%s\\n' \"make $*\" >> \"$STUB_LOG\"\n",
        )

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(REPOSITORY_ROOT / "ops" / "ci" / "registry-gc.sh"), *arguments],
            cwd=REPOSITORY_ROOT,
            env=self.env.environment(REGISTRY="registry.example.invalid:5000"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_help_exits_zero(self) -> None:
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_unknown_argument_fails(self) -> None:
        result = self.run_script("--nonsense")
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_plan_runs_the_read_only_planner(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertIn("registry-clean-plan", calls)
        self.assertNotIn("registry-gc ", calls)
        self.assertIn("nothing was changed", result.stdout)

    def test_apply_without_confirmation_changes_nothing(self) -> None:
        result = self.run_script("--apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("REGISTRY_GC_CONFIRM", result.stdout)
        self.assertEqual(self.env.calls(), [])


class DindPruneScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = StubEnvironment()
        self.addCleanup(self.env.close)
        self.env.stub(
            "docker",
            "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\n"
            "if [ \"${1:-}\" = ps ]; then printf '%s\\n' 'abc123'; fi\n",
        )

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(REPOSITORY_ROOT / "ops" / "ci" / "dind-prune.sh"), *arguments],
            cwd=REPOSITORY_ROOT,
            env=self.env.environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_help_exits_zero(self) -> None:
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_unknown_argument_fails(self) -> None:
        result = self.run_script("--nonsense")
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_plan_reports_usage_without_pruning(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("nothing was pruned", result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertIn("system df", calls)
        self.assertIn("buildx du", calls)
        self.assertNotIn("prune", calls)

    def test_apply_prunes_cache_with_a_ceiling(self) -> None:
        result = self.run_script("--apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertIn("buildx prune", calls)
        self.assertIn("--keep-storage 20GB", calls)
        self.assertIn("--filter until=168h", calls)
        self.assertIn("image prune", calls)
        for line in self.env.calls():
            self.assertNotIn("volume rm", line, line)
            self.assertNotIn("system prune", line, line)

    def test_missing_container_fails_closed(self) -> None:
        self.env.stub("docker", "exit 0\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("no container with label", result.stdout)


POSTGRES_STUB = (
    "printf '%s\\n' \"$*\" >> \"$STUB_LOG\"\n"
    "case \"${1:-}\" in\n"
    "  ps)\n"
    "    if [ \"${STUB_CONTAINER_PRESENT:-1}\" = 1 ]; then\n"
    "      printf '%s\\n' 'ssl-proxy-platform-postgres'\n"
    "    fi\n"
    "    exit 0 ;;\n"
    "  exec) ;;\n"
    "  *) exit 0 ;;\n"
    "esac\n"
    "case \"$*\" in\n"
    "  *' psql '*)\n"
    "    case \"$*\" in\n"
    "      *pg_extension*) printf '0\\n' ;;\n"
    "      *pg_total_relation_size*) printf '1024\\n' ;;\n"
    "      *'-f -'*) cat >/dev/null || true; printf 'relation report line\\n' ;;\n"
    "      *current_database*) printf 'sync,1\\n' ;;\n"
    "      *) cat >/dev/null 2>/dev/null || true ;;\n"
    "    esac ;;\n"
    "  *df*)\n"
    "    printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\\n'\n"
    "    printf '/dev/x 1000000000 900000000 100000000 90%% /var/lib/postgresql/data\\n' ;;\n"
    "esac\n"
    "exit 0\n"
)


class PostgresScriptTest(unittest.TestCase):
    """Shared docker stub that answers the read-only SQL paths."""

    container_present = True

    def setUp(self) -> None:
        self.env = StubEnvironment()
        self.addCleanup(self.env.close)
        self.env.stub("docker", POSTGRES_STUB)
        self.output = self.env.root / "snapshots"

    def environment(self) -> dict[str, str]:
        return self.env.environment(
            AUDIT_OUTPUT_DIR=str(self.output),
            STUB_CONTAINER_PRESENT="1" if self.container_present else "0",
        )

    def run_script(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(REPOSITORY_ROOT / "ops" / "sql" / script), *arguments],
            cwd=REPOSITORY_ROOT,
            env=self.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )


class PgSizeReportScriptTest(PostgresScriptTest):
    def test_report_records_a_growth_sample(self) -> None:
        result = self.run_script("pg-size-report.sh")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("report generated", result.stdout)
        growth = (self.output / "pg-growth.csv").read_text(encoding="utf-8")
        lines = growth.splitlines()
        self.assertEqual("timestamp,database,bytes", lines[0])
        self.assertRegex(lines[1], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z,sync,1$")

    def test_missing_container_fails_with_a_clear_message(self) -> None:
        self.container_present = False
        result = self.run_script("pg-size-report.sh")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("is not reachable", result.stdout)
        self.assertFalse((self.output / "pg-growth.csv").exists())


class PgRepackScriptTest(PostgresScriptTest):
    def test_plan_is_read_only(self) -> None:
        result = self.run_script("pg-repack.sh")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("pg_repack is not installed", result.stdout)
        self.assertIn("nothing was changed", result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertNotIn("repack_table", calls)
        self.assertNotIn("VACUUM", calls)

    def test_help_exits_zero(self) -> None:
        result = self.run_script("pg-repack.sh", "--help")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_apply_requires_the_confirmation_token(self) -> None:
        result = self.run_script("pg-repack.sh", "--apply", "--table", "octopus_core.sync_events")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("REPACK-TABLE", result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertNotIn("repack_table", calls)
        self.assertNotIn("VACUUM", calls)

    def test_apply_rejects_an_injected_identifier(self) -> None:
        result = self.run_script(
            "pg-repack.sh",
            "--apply",
            "--table",
            "octopus_core.sync_events; DROP TABLE x",
            "--confirm",
            "REPACK-TABLE",
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("invalid identifier", result.stdout)
        calls = "\n".join(self.env.calls())
        self.assertNotIn("DROP TABLE", calls)
        self.assertNotIn("repack_table", calls)
        self.assertNotIn("VACUUM", calls)

    def test_apply_requires_an_existing_relation(self) -> None:
        result = self.run_script(
            "pg-repack.sh",
            "--apply",
            "--table",
            "octopus_core.sync_events",
            "--confirm",
            "REPACK-TABLE",
        )
        calls = "\n".join(self.env.calls())
        self.assertIn("no such relation", result.stdout)
        self.assertNotIn("VACUUM", calls)


class DiskAuditMakeTargetTest(unittest.TestCase):
    def test_make_disk_audit_runs_the_read_only_script(self) -> None:
        result = subprocess.run(
            ["make", "-n", "disk-audit"],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ops/disk/audit.sh", result.stdout)


if __name__ == "__main__":
    unittest.main()
