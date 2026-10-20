import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("proxy_rag_measure", ROOT / "ops/sql/proxy-rag-measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class ProxyRagMeasureTest(unittest.TestCase):
    def test_proxy_producer_corpus_is_bundled_without_drift(self):
        canonical = ROOT / "sql/postgres/contracts/fixtures/proxy-events-v1.json"
        bundled = ROOT / "services/octopus/src/test/resources/contracts/proxy-events-v1.json"
        self.assertEqual(canonical.read_bytes(), bundled.read_bytes())
    def test_revisions_require_each_checkout_root(self):
        for unavailable in (str(ROOT), FileNotFoundError(), subprocess.CalledProcessError(128, "git")):
            with self.subTest(unavailable=unavailable):
                def git(command, cwd=ROOT):
                    if cwd == ROOT / "services/octopus":
                        if isinstance(unavailable, Exception):
                            raise unavailable
                        return unavailable
                    if command == ["git", "rev-parse", "--show-toplevel"]:
                        return str(cwd.resolve())
                    return "head-revision" if command[-1] == "HEAD" else " M tracked-file"

                with patch.object(measure, "run", side_effect=git) as run:
                    revisions = measure.metadata()["revisions"]
                self.assertEqual(revisions["octopus"], {"status": "unavailable_not_checked_out"})
                for name in ("parent", "integration_console"):
                    self.assertEqual(revisions[name], {"head": "head-revision", "dirty": True})
                for command in (["git", "rev-parse", "HEAD"], ["git", "status", "--porcelain"]):
                    self.assertNotIn(call(command, ROOT / "services/octopus"), run.call_args_list)

    def test_audit_cursor_accepts_different_ids_without_python_ordering(self):
        args = SimpleNamespace(window_start="2026-10-19T00:00Z", window_end="2026-10-20T00:00Z",
                               page_size=1, max_pages=3, statement_timeout_ms=1000)
        pages = [dict(source_rows=1, document_rows=1,
                      source_cursor=[args.window_start, source_id],
                      document_cursor=[args.window_start, document_id])
                 for source_id, document_id in (("z", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
                                                ("a", "00000000-0000-0000-0000-000000000001"))]
        pages.append(dict(source_rows=0, document_rows=0, source_cursor=None, document_cursor=None))
        with patch.object(measure, "psql", side_effect=pages):
            self.assertEqual(measure.measure(args)["status"], "window_pages_exhausted")

    def test_audit_cursor_rejects_regression_and_exact_repeat(self):
        args = SimpleNamespace(window_start="2026-10-19T00:00Z", window_end="2026-10-20T00:00Z",
                               page_size=1, max_pages=1, statement_timeout_ms=1000)
        for field, initial_id in (("source_cursor", ""),
                                  ("document_cursor", "00000000-0000-0000-0000-000000000000")):
            for cursor in (("2026-10-18T23:59Z", "z"), (args.window_start, initial_id)):
                with self.subTest(field=field, cursor=cursor):
                    page = dict(source_rows=1, document_rows=1, source_cursor=None, document_cursor=None)
                    page[field] = cursor
                    with patch.object(measure, "psql", return_value=page):
                        with self.assertRaisesRegex(ValueError, "nonadvancing audit cursor"):
                            measure.measure(args)

    def test_missing_capacity_is_a_blocker(self):
        result = measure.capacity({})
        self.assertEqual(result["status"], "blocked_unmeasured")
        self.assertIsNone(result["drain_seconds"])
        self.assertIn("current_reserve_jobs_per_second", result["missing"])

    def test_measured_capacity_reserves_current_traffic_and_pauses(self):
        fields = measure.capacity({})["missing"]
        values = dict.fromkeys(fields, 1)
        values.update(jobs_per_second=10, current_reserve_jobs_per_second=4,
                      interactive_p99_ms=100, pause_p99_ms=200,
                      current_ingest_lag_seconds=1, pause_ingest_lag_seconds=10,
                      backend_error_rate=0, pause_backend_error_rate=0.01,
                      memory_bytes=100, pause_memory_bytes=200,
                      pending_jobs=60, queue_growth_per_second=0)
        self.assertEqual(measure.capacity(values)["drain_seconds"], 10)
        values["queue_growth_per_second"] = 1
        self.assertEqual(measure.capacity(values)["status"], "pause")
        self.assertIsNone(measure.capacity(values)["drain_seconds"])
        values["memory_bytes"] = float("nan")
        with self.assertRaises(ValueError):
            measure.capacity(values)

    def test_shared_corpus_and_psl_copies_are_identical(self):
        canonical = ROOT / "sql/postgres/contracts/fixtures/proxy-authority-v1.json"
        octopus = ROOT / "services/octopus/src/test/resources/contracts/proxy-authority-v1.json"
        search = ROOT / "apps/integration-console/atheros-search/internal/queryscope/testdata/proxy-authority-v1.json"
        self.assertEqual(canonical.read_bytes(), octopus.read_bytes())
        self.assertEqual(canonical.read_bytes(), search.read_bytes())
        corpus = json.loads(canonical.read_text())
        paths = [ROOT / "services/octopus/src/main/resources/proxy-authority/public_suffix_list.dat",
                 ROOT / "apps/integration-console/atheros-search/internal/queryscope/public_suffix_list.dat"]
        for path in paths:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), corpus["psl_sha256"])
        self.assertGreaterEqual(len(corpus["cases"]), 60)

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            measure.timestamp("2026-10-19T00:00:00")


if __name__ == "__main__":
    unittest.main()
