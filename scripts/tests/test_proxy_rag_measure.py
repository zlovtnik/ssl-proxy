import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("proxy_rag_measure", ROOT / "ops/sql/proxy-rag-measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class ProxyRagMeasureTest(unittest.TestCase):
    def campaign_fixture(self):
        bounds = {"window_start": "2026-10-19T00:00:00Z", "window_end": "2026-10-19T01:00:00Z"}
        request = {**bounds, "snapshot_sha256": "a" * 64, "input_revision": "legacy_unknown",
                   "revisions": {"parent": "b" * 40, "octopus": "c" * 40, "integration_console": "d" * 40},
                   "schema_manifest_sha256": {"octopus_core": "e" * 64, "atheros_search": "f" * 64}}
        page = {**bounds, "audit_version": "proxy-rag-coverage-v1", "model": measure.MODEL,
                "source_rows": 4, "source_page": [{"sources": 3, "disposition": "eligible_unvalidated_authority"},
                                                  {"sources": 1, "disposition": "excluded_missing_host"}],
                "document_rows": 3, "document_page": [
                    {"documents": 1, "source_kind": "proxy_event", "job_disposition": "failed_exhausted"},
                    {"documents": 1, "source_kind": "proxy_event", "job_disposition": "pending"},
                    {"documents": 1, "source_kind": "proxy_blocked_host_window", "job_disposition": "cancelled"}]}
        report = {"audit_version": "proxy-rag-measure-v1", "model": measure.MODEL, "embedding_dimensions": 768,
                  "measured_at": "2026-10-19T01:01:00Z", "snapshot_sha256": request["snapshot_sha256"],
                  "retained_source_range": {"source_first": "2026-10-19T00:01:00Z",
                                            "source_last": "2026-10-19T00:59:00Z"},
                  "coverage": {"status": "window_pages_exhausted", "pages": [page]},
                  "blocked_windows": {"hours": [{**bounds, "audit_version": "proxy-window-coverage-v1",
                                                "complete_input": True}], "hour_budget_exhausted": False},
                  "capacity": {"status": "blocked_unmeasured"}}
        return request, report

    def test_campaign_cli_pins_offline_baseline_and_dispositions(self):
        request, report = self.campaign_fixture()
        report_bytes = json.dumps(report).encode()
        with tempfile.TemporaryDirectory() as directory:
            request_path = Path(directory) / "request.json"
            baseline_path = Path(directory) / "baseline.json"
            request_path.write_text(json.dumps(request))
            baseline_path.write_bytes(report_bytes)
            result = subprocess.run([sys.executable, str(ROOT / "ops/sql/proxy-rag-measure.py"),
                                     "--freeze-campaign", str(request_path), "--baseline", str(baseline_path)],
                                    check=True, capture_output=True, text=True)
        campaign = json.loads(result.stdout)
        self.assertEqual(campaign, measure.freeze_campaign(request, report_bytes))
        self.assertEqual(campaign["status"], "frozen_candidate_requires_review")
        self.assertEqual(campaign["source_kinds"], ["proxy_blocked_host_window", "proxy_event"])
        self.assertEqual(campaign["baseline"]["report_sha256"], hashlib.sha256(report_bytes).hexdigest())
        self.assertEqual(campaign["baseline"]["capacity_status"], "blocked_unmeasured")
        self.assertEqual(campaign["baseline"]["source_dispositions"]["excluded_missing_host"], 1)
        self.assertEqual(campaign["baseline"]["terminal_jobs_by_kind"]["proxy_event"]["failed_exhausted"], 1)
        self.assertEqual(campaign["baseline"]["terminal_jobs_by_kind"]["proxy_blocked_host_window"]["cancelled"], 1)
        self.assertEqual(campaign["unrecoverable_sources"],
                         {"status": "unknown_without_retained_ledger", "expired": None, "missing": None})
        request["unrecoverable_sources"] = {"ledger_sha256": "1" * 64, "expired": 2, "missing": 1}
        attested = measure.freeze_campaign(request, report_bytes)
        self.assertEqual(attested["unrecoverable_sources"]["expired"], 2)
        self.assertNotEqual(attested["campaign_sha256"], campaign["campaign_sha256"])
        self.assertNotEqual(measure.freeze_campaign(request, report_bytes + b"\n")["campaign_sha256"],
                            attested["campaign_sha256"])

    def test_campaign_rejects_invalid_pins_and_incomplete_or_mismatched_baseline(self):
        for section, key, value, error in (
            ("request", "input_revision", "nomic-prefix-v1:missing", "invalid revision"),
            ("request", "snapshot_sha256", "b" * 64, "snapshot pins differ"),
            ("retained_source_range", "source_last", "2026-10-18T00:59:00Z", "overlap"),
            ("coverage", "status", "page_budget_exhausted", "complete source"),
            ("page", "window_end", "2026-10-19T02:00:00Z", "match campaign"),
            ("page", "source_rows", 5, "do not reconcile"),
            ("document", "source_kind", "wireless_event", "non-proxy"),
            ("hour", "complete_input", False, "incomplete or mismatched"),
        ):
            with self.subTest(section=section, key=key):
                request, report = self.campaign_fixture()
                page = report["coverage"]["pages"][0]
                sections = {**report, "request": request, "page": page, "document": page["document_page"][0],
                            "hour": report["blocked_windows"]["hours"][0]}
                sections[section][key] = value
                with self.assertRaisesRegex(ValueError, error):
                    measure.freeze_campaign(request, json.dumps(report).encode())

    def test_replay_comparison_requires_complete_matching_scope_and_detects_identity_change(self):
        _, report = self.campaign_fixture()
        report["page_size"] = 10
        page = report["coverage"]["pages"][0]
        page.update(source_page_sha256="1" * 64, document_page_sha256="2" * 64)
        repeated = json.loads(json.dumps(report))
        self.assertEqual(measure.replay_comparison(report, repeated)["status"], "unchanged")
        repeated["coverage"]["pages"][0]["document_page_sha256"] = "3" * 64
        self.assertEqual(measure.replay_comparison(report, repeated)["changed"], ["document_job_vector"])
        repeated["page_size"] = 11
        with self.assertRaisesRegex(ValueError, "same frozen scope"):
            measure.replay_comparison(report, repeated)
        repeated["blocked_windows"]["hours"][0]["complete_input"] = False
        with self.assertRaisesRegex(ValueError, "requires complete"):
            measure.replay_comparison(report, repeated)

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

    def test_live_specs_report_scope_and_input_identity_without_runtime_attestation(self):
        settings = {
            "ATHSEARCH_WORKER_ENABLED": "true", "ATHSEARCH_WORKER_SOURCE_KINDS": "proxy_event",
            "ATHSEARCH_EMBEDDING_BATCH_SIZE": "32", "ATHSEARCH_EMBEDDING_REQUEST_CONCURRENCY": "4",
            "ATHSEARCH_EMBEDDING_QUERY_RESERVED_SLOTS": "1",
            "ATHSEARCH_EMBEDDING_INPUT_REVISION": "legacy_unknown",
            "ATHSEARCH_EMBEDDING_PREFIX_OWNER": "legacy",
        }
        pod = {"metadata": {"name": "ssl-proxy-atheros-search-abc"},
               "spec": {"containers": [{"name": "atheros-search", "image": "search@sha256:fixture",
                   "env": [dict(name=key, value=value) for key, value in settings.items()] + [
                       dict(name="ATHSEARCH_POSTGRES_PASSWORD", value="must-not-appear")]}]},
               "status": {"containerStatuses": [{"name": "atheros-search", "imageID": "running-image"}]}}

        def run(command, cwd=ROOT, timeout=30):
            if command[0] == "kubectl":
                return json.dumps({"items": [pod]})
            if command == ["git", "rev-parse", "--show-toplevel"]:
                return str(cwd.resolve())
            return "head" if command[-1] == "HEAD" else ""

        with patch.object(measure, "run", side_effect=run):
            result = measure.metadata(live=True)
        self.assertEqual(result["live"]["workloads"][0]["settings"], settings)
        self.assertEqual(result["worker_settings"], [settings])
        self.assertEqual(result["live"]["status"], "observed_pod_specs_only")
        self.assertEqual(result["actual_processor_enablement"], "unavailable_requires_runtime_attestation")
        self.assertEqual(result["backend_artifact_preprocessing"], "unmeasured")
        self.assertNotIn("must-not-appear", json.dumps(result))
        self.assertIn("cyber-stack/base/atheros-search/deployment.yaml", result["desired_files"])

    def test_measured_capacity_reserves_current_traffic_and_pauses(self):
        fields = measure.capacity({})["missing"]
        values = dict.fromkeys(fields, 1)
        values.update(jobs_per_second=10, current_reserve_jobs_per_second=4,
                      interactive_p99_ms=100, pause_p99_ms=200,
                      current_ingest_lag_seconds=1, pause_ingest_lag_seconds=10,
                      backend_error_rate=0, pause_backend_error_rate=0.01,
                      memory_bytes=100, pause_memory_bytes=200,
                      pending_jobs=100, pending_backfill_jobs=60, backfill_jobs_per_second=6,
                      current_jobs_per_second=4, queue_growth_per_second=0)
        self.assertEqual(measure.capacity(values)["drain_seconds"], 10)
        values["current_jobs_per_second"] = 5
        self.assertIn("backfill_over_budget", measure.capacity(values)["pause_reasons"])
        values["backfill_jobs_per_second"] = 5
        self.assertEqual(measure.capacity(values)["drain_seconds"], 12)
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
