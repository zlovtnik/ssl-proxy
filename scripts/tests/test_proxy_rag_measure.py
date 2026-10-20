import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("proxy_rag_measure", ROOT / "ops/sql/proxy-rag-measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class ProxyRagMeasureTest(unittest.TestCase):
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
