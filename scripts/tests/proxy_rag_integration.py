#!/usr/bin/env python3
"""Required isolated canonical PostgreSQL audit tests; missing Docker is a failure."""
import json
import os
from pathlib import Path
import subprocess
import unittest

import yaml
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import ExecWaitStrategy

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "pgvector/pgvector:0.8.6-pg16-bookworm@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b"


class ProxyRagIntegration(unittest.TestCase):
    @classmethod
    def command(cls, command, data=None):
        result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout.strip()

    @classmethod
    def sql(cls, statement, role="postgres", variables=None):
        command = ["docker", "exec", "-i", cls.container, "psql", "-X", "-qAt", "-U", role,
                   "-d", "sync", "-v", "ON_ERROR_STOP=1"]
        for key, value in (variables or {}).items():
            command += ["-v", f"{key}={value}"]
        return cls.command(command, statement)

    @classmethod
    def setUpClass(cls):
        cls.postgres = (DockerContainer(IMAGE)
                        .with_env("POSTGRES_PASSWORD", "contract-test")
                        .with_env("POSTGRES_DB", "sync")
                        .waiting_for(ExecWaitStrategy([
                            "env", "PGPASSWORD=contract-test", "PGCONNECT_TIMEOUT=2",
                            "psql", "-X", "-h", "127.0.0.1", "-U", "postgres", "-d", "sync",
                            "-Atc", "SELECT 1",
                        ]).with_startup_timeout(60)))
        cls.postgres.start()
        cls.addClassCleanup(cls.postgres.stop)
        cls.container = cls.postgres.get_wrapped_container().id
        cls.sql("CREATE EXTENSION vector;")
        for domain in ("octopus_core", "atheros_search"):
            directory = ROOT / "sql/postgres" / domain
            manifest = yaml.safe_load((directory / "manifest.yaml").read_text())
            for relative in manifest["apply_order"]:
                cls.sql((directory / relative).read_text())
        cls.sql("CREATE ROLE proxy_audit LOGIN; GRANT USAGE ON SCHEMA octopus_core,atheros_search TO proxy_audit; "
                "GRANT SELECT ON ALL TABLES IN SCHEMA octopus_core,atheros_search TO proxy_audit;")
        cls.sql("""INSERT INTO octopus_core.proxy_events(event_id,event_time,event_type,host)
SELECT 'volume-'||n, '2026-10-01'::timestamptz+n*interval '1 second','http_proxied','example.com'
FROM generate_series(1,20000) n;
INSERT INTO octopus_core.proxy_events(event_id,event_time,event_type,host,correlation_id) VALUES
('a','2026-10-19T00:00Z','block','example.com',null),
('b','2026-10-19T00:00Z','http_blocked','example.com',null),
('c','2026-10-19T00:00Z','session.blocked','hmac:deadbeef',null),
('d','2026-10-19T00:00Z','http_proxied','example.com',null),
('e','2026-10-19T00:00Z','http_error','example.com',null),
('f','2026-10-19T00:00Z','tunnel_open','example.com','cross-end'),
('g','2026-10-19T00:00Z','tunnel_close','example.com','cross-start'),
('h','2026-10-19T00:00Z','http_error','',null),
('i','2026-10-19T00:00Z','http_error','bad host',null),
('j','2026-10-19T00:00Z','stats_live','example.com',null),
('old-open','2026-10-18T23:59Z','tunnel_open','example.com','cross-start'),
('new-close','2026-10-20T00:01Z','tunnel_close','example.com','cross-end');
INSERT INTO atheros_search.search_documents(document_id,source_kind,source_id,source_table,source_key,
 normalized_text,normalized_sha256,search_vector,observed_at) VALUES
('00000000-0000-0000-0000-000000000001','proxy_event','a','proxy_events','a','proxy event block example.com unknown allowed',
 encode(sha256(convert_to('proxy event block example.com unknown allowed','UTF8')),'hex'),to_tsvector('simple','proxy'),'2026-10-19T00:00Z'),
('00000000-0000-0000-0000-000000000002','proxy_event','b','proxy_events','b','outdated',
 encode(sha256(convert_to('outdated','UTF8')),'hex'),to_tsvector('simple','outdated'),'2026-10-19T00:00Z');
INSERT INTO atheros_search.embedding_jobs(job_id,document_id,embedding_kind,embedding_model,content_sha256,status)
SELECT document_id,document_id,'event','nomic-embed-text-v2-moe',normalized_sha256,'completed'
FROM atheros_search.search_documents;
INSERT INTO atheros_search.embeddings(document_id,embedding_kind,embedding_model,content_sha256,embedding,embedded_at)
SELECT document_id,'event','nomic-embed-text-v2-moe',normalized_sha256,
 ('['||'1,'||repeat('0,',766)||'0]')::vector,CURRENT_TIMESTAMP FROM atheros_search.search_documents;
ANALYZE octopus_core.proxy_events;
ANALYZE atheros_search.search_documents;
""")
        cls.sql("""
INSERT INTO octopus_core.proxy_events(event_id,event_time,event_type,host,blocked) VALUES
('window-a','2026-10-17T01:10Z','block','example.com',true),
('window-b','2026-10-17T01:20Z','http_blocked','example.com',true);
INSERT INTO atheros_search.search_documents(document_id,source_kind,source_id,source_table,source_key,
 normalized_text,normalized_sha256,search_vector,observed_at)
SELECT md5('job-state-'||n)::uuid,'proxy_event','job-state-'||n,'proxy_events','job-state-'||n,
 'fixture',encode(sha256(convert_to('fixture','UTF8')),'hex'),to_tsvector('simple','fixture'),'2026-10-16T00:00Z'
FROM generate_series(1,9) n;
INSERT INTO atheros_search.embedding_jobs(job_id,document_id,embedding_kind,embedding_model,content_sha256,
 status,attempt_count,owner_id,lease_token,lease_expires_at)
SELECT md5('job-state-'||n)::uuid,md5('job-state-'||n)::uuid,'event','nomic-embed-text-v2-moe',
 CASE WHEN n=8 THEN repeat('0',64) ELSE encode(sha256(convert_to('fixture','UTF8')),'hex') END,
 CASE n WHEN 1 THEN 'pending' WHEN 2 THEN 'failed' WHEN 3 THEN 'cancelled' WHEN 4 THEN 'leased'
   WHEN 5 THEN 'pending' WHEN 6 THEN 'failed' ELSE 'completed' END,
 CASE WHEN n IN (5,6) THEN 5 ELSE 0 END,
 CASE WHEN n=4 THEN 'fixture-owner' END,
 CASE WHEN n=4 THEN md5('fixture-token')::uuid END,
 CASE WHEN n=4 THEN CURRENT_TIMESTAMP+interval '1 hour' END
FROM generate_series(1,9) n;
INSERT INTO atheros_search.embeddings(document_id,embedding_kind,embedding_model,content_sha256,embedding,embedded_at)
SELECT document_id,'event','nomic-embed-text-v2-moe',normalized_sha256,
 ('[1,'||repeat('0,',766)||'0]')::vector,CURRENT_TIMESTAMP
FROM atheros_search.search_documents WHERE source_key='job-state-9';
INSERT INTO atheros_search.search_vectors_event(document_id,embedding_model,content_sha256,embedding,embedded_at)
SELECT document_id,'nomic-embed-text-v2-moe',normalized_sha256,
 ('[0,1,'||repeat('0,',765)||'0]')::vector,CURRENT_TIMESTAMP
FROM atheros_search.search_documents WHERE source_key='job-state-9';
""")

    def variables(self, size=100):
        return dict(window_start="2026-10-19T00:00:00Z", window_end="2026-10-20T00:00:00Z",
                    after_time="2026-10-19T00:00:00Z", after_id="", document_after_time="2026-10-19T00:00:00Z",
                    document_after_id="00000000-0000-0000-0000-000000000000", page_size=size,
                    model="nomic-embed-text-v2-moe", statement_timeout_ms=5000,
                    horizon_start="2026-10-18T23:00:00Z", horizon_end="2026-10-20T01:00:00Z", counterpart_limit=20)

    def test_source_ledger_and_vector_stages(self):
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-rag-coverage.sql").read_text(), "proxy_audit", self.variables()))
        self.assertEqual(result["source_rows"], 10)
        self.assertEqual(sum(r["sources"] for r in result["source_page"]), 10)
        excluded = sum(r["sources"] for r in result["source_page"] if r["disposition"].startswith("excluded"))
        self.assertEqual(excluded, 3)
        self.assertEqual(sum(r["absent_document"] for r in result["source_page"]), 8)
        self.assertEqual(sum(r["outdated_legacy_text"] for r in result["source_page"]), 1)
        self.assertEqual(sum(r["outdated_legacy_detail"] for r in result["source_page"]), 2)
        self.assertEqual(sum(r["completed_job_vector_gap"] for r in result["document_page"]), 2)
        self.assertEqual(sum(r["vector_presence_parity_gap"] for r in result["document_page"]), 2)
        self.assertTrue(all(r["preprocessing_version"] == "unknown_legacy" for r in result["document_page"]))
        self.assertEqual(result["availability"]["terminal_measured_bytes"], "unknown_legacy")

    def test_same_timestamp_keyset(self):
        variables = self.variables(3)
        sources, documents = 0, 0
        for _ in range(5):
            page = json.loads(self.sql((ROOT / "ops/sql/proxy-rag-coverage.sql").read_text(), "proxy_audit", variables))
            sources += page["source_rows"]
            documents += page["document_rows"]
            if page["source_cursor"]:
                variables["after_time"], variables["after_id"] = page["source_cursor"]
            if page["document_cursor"]:
                variables["document_after_time"], variables["document_after_id"] = page["document_cursor"]
        self.assertEqual((sources, documents), (10, 2))

    def test_lifecycle_crosses_both_boundaries(self):
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text(), "proxy_audit", self.variables()))
        self.assertEqual(result["seed_rows"], 2)
        self.assertTrue(result["horizon_covers_window"])
        self.assertEqual(result["cross_boundary_pairs"], 2)
        self.assertEqual(result["single_ordered_pair_within_horizon"], 2)
        variables = self.variables()
        variables["horizon_start"], variables["horizon_end"] = variables["window_start"], variables["window_end"]
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text(), "proxy_audit", variables))
        self.assertTrue(result["horizon_covers_window"])
        self.assertEqual(result["missing_side_unknown_beyond_horizon"], 2)

    def test_lifecycle_requires_horizon_to_cover_full_window(self):
        for bounds in (dict(horizon_start="2026-10-19T00:01Z"),
                       dict(horizon_end="2026-10-19T23:59Z")):
            with self.subTest(bounds=bounds):
                variables = self.variables()
                variables.update(bounds)
                result = json.loads(self.sql((ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text(),
                                             "proxy_audit", variables))
                self.assertFalse(result["horizon_covers_window"])
                self.assertEqual(result["seed_rows"], 2)
                self.assertEqual(result["candidate_correlations"], 0)
                self.assertEqual(result["single_ordered_pair_within_horizon"], 0)
                self.assertEqual(result["counterpart_rows_returned"], 0)

    def test_lifecycle_rejects_blank_correlations_and_reports_saturation(self):
        self.sql("""INSERT INTO octopus_core.proxy_events(event_id,event_time,event_type,host,correlation_id) VALUES
('blank-open','2026-10-15T01:00Z','tunnel_open','example.com',''),
('blank-close','2026-10-15T01:00Z','tunnel_close','example.com',''),
('space-open','2026-10-15T01:00Z','tunnel_open','example.com',E' \\t'),
('space-close','2026-10-15T01:00Z','tunnel_close','example.com',E' \\t'),
('saturated-a','2026-10-15T01:00Z','tunnel_open','example.com','saturated'),
('saturated-b','2026-10-15T01:01Z','tunnel_close','example.com','saturated'),
('saturated-c','2026-10-15T01:02Z','tunnel_open','example.com','saturated');""")
        variables = self.variables()
        variables.update(window_start="2026-10-15T00:00Z", window_end="2026-10-16T00:00Z",
                         horizon_start="2026-10-15T00:00Z", horizon_end="2026-10-16T00:00Z",
                         after_time="2026-10-15T00:00Z", counterpart_limit=2)
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text(),
                                    "proxy_audit", variables))
        self.assertEqual(result["seed_rows"], 7)
        self.assertEqual(result["missing_correlation_observations"], 4)
        self.assertEqual(result["candidate_correlations"], 1)
        self.assertEqual(result["counterpart_page_saturated"], 1)
        self.assertEqual(result["single_ordered_pair_within_horizon"], 0)

    def test_lifecycle_horizon_excludes_retained_history_before_aggregation(self):
        self.sql("""INSERT INTO octopus_core.proxy_events(event_id,event_time,event_type,host,correlation_id)
SELECT 'old-lifecycle-'||n, '2026-10-02'::timestamptz+n*interval '1 second',
 'tunnel_open','example.com','cross-start' FROM generate_series(1,1000) n;
ANALYZE octopus_core.proxy_events;""")
        query = (ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text()
        result = json.loads(self.sql(query, "proxy_audit", self.variables()))
        self.assertEqual(result["single_ordered_pair_within_horizon"], 2)
        self.assertEqual(result["counterpart_rows_returned"], 4)
        self.assertEqual(result["duplicate_or_conflicting"], 0)
        plan = json.loads(self.sql(query.replace("WITH seeds AS", "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) WITH seeds AS"),
                                   "proxy_audit", self.variables()))[0]

        def nodes(node):
            yield node
            for child in node.get("Plans", []):
                yield from nodes(child)

        scans = [node for node in nodes(plan["Plan"]) if node.get("Relation Name") == "proxy_events"]
        self.assertTrue(scans)
        self.assertTrue(all(node["Actual Rows"] + node.get("Rows Removed by Filter", 0) <= 12
                            for node in scans), scans)

    def test_lifecycle_same_timestamp_seed_keyset(self):
        variables = self.variables(1)
        query = (ROOT / "ops/sql/proxy-tunnel-completeness.sql").read_text()
        pages = []
        for _ in range(3):
            page = json.loads(self.sql(query, "proxy_audit", variables))
            pages.append(page)
            if page["cursor"]:
                variables["after_time"], variables["after_id"] = page["cursor"]
        self.assertEqual([page["seed_rows"] for page in pages], [1, 1, 0])
        self.assertEqual([page["cursor"][1] for page in pages[:2]], ["f", "g"])

    def test_explain_bounded_volume(self):
        query = (ROOT / "ops/sql/proxy-rag-coverage.sql").read_text().replace(
            "WITH source_page AS", "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) WITH source_page AS")
        plan = json.loads(self.sql(query, "proxy_audit", self.variables(3)))[0]
        def nodes(node):
            yield node
            for child in node.get("Plans", []):
                yield from nodes(child)
        scans = [n for n in nodes(plan["Plan"]) if n.get("Relation Name") == "proxy_events"]
        self.assertTrue(scans)
        self.assertTrue(all(n["Actual Rows"] + n.get("Rows Removed by Filter", 0) <= 10 for n in scans), scans)
        if os.getenv("PROXY_RAG_PLAN_OUTPUT"):
            Path(os.environ["PROXY_RAG_PLAN_OUTPUT"]).write_text(json.dumps(plan, indent=2) + "\n")

    def test_terminal_and_checksum_dispositions(self):
        variables = self.variables()
        variables.update(window_start="2026-10-16T00:00Z",window_end="2026-10-17T00:00Z",
                         after_time="2026-10-16T00:00Z",document_after_time="2026-10-16T00:00Z")
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-rag-coverage.sql").read_text(), "proxy_audit", variables))
        self.assertEqual(result["document_rows"], 9)
        dispositions = {r["job_disposition"]:r["documents"] for r in result["document_page"]}
        self.assertEqual(dispositions, dict(pending=1,failed=1,cancelled=1,leased=1,
                                           pending_exhausted=1,failed_exhausted=1,completed=2,absent=1))
        self.assertEqual(sum(r["stale_checksum_job_present"] for r in result["document_page"]), 1)
        self.assertEqual(sum(r["vector_value_parity_gap"] for r in result["document_page"]), 1)
        self.assertEqual(sum(r["completed_job_vector_gap"] for r in result["document_page"]), 1)

    def test_window_input_is_bounded_before_aggregation(self):
        variables = self.variables()
        variables.update(window_start="2026-10-17T01:00Z",window_end="2026-10-17T02:00Z",page_size=10)
        query = (ROOT / "ops/sql/proxy-rag-window-coverage.sql").read_text()
        result = json.loads(self.sql(query, "proxy_audit", variables))
        self.assertEqual((result["scanned_rows"],result["groups"],result["absent_document"]),(2,1,1))
        self.assertTrue(result["complete_input"])
        self.sql("""INSERT INTO atheros_search.search_documents(document_id,source_kind,source_id,source_table,source_key,
 normalized_text,normalized_sha256,search_vector,observed_at)
VALUES ('00000000-0000-0000-0000-000000000010','proxy_blocked_host_window','window-fixture','proxy_events',
 'proxy-window:'||md5(jsonb_build_array('example.com','','2026-10-17T01:00Z'::timestamptz)::text),
 'stale',repeat('0',64),to_tsvector('simple','stale'),'2026-10-17T01:20Z')""")
        result = json.loads(self.sql(query, "proxy_audit", variables))
        self.assertEqual((result["absent_document"],result["outdated_legacy_text"]),(0,1))
        variables["page_size"] = 1
        result = json.loads(self.sql(query, "proxy_audit", variables))
        self.assertFalse(result["complete_input"])
        self.assertEqual(result["groups"], 0)

    def test_database_baseline_is_read_only(self):
        result = json.loads(self.sql((ROOT / "ops/sql/proxy-rag-baseline.sql").read_text(), "proxy_audit"))
        self.assertEqual(result["vector_extension"], "0.8.6")
        self.assertTrue(result["source_first"].startswith("2026-10-01"))
        self.assertEqual(len(result["attestations"]), 2)
        with self.assertRaises(RuntimeError):
            self.sql("DELETE FROM octopus_core.proxy_events", "proxy_audit")

    def migration_upgrade(self, settings="", empty=False):
        # Every probe rolls back, including psql disconnect after ON_ERROR_STOP.
        # Only this suite's ephemeral database is modified.
        migration = (ROOT / "sql/postgres/octopus_core/01_tables/021_proxy_evidence.sql").read_text()
        return self.sql(
            "BEGIN; ALTER TABLE octopus_core.proxy_events DROP COLUMN observation_revision, "
            "DROP COLUMN evidence; "
            + ("TRUNCATE octopus_core.proxy_events; " if empty else "")
            + settings + migration
            + "SELECT count(*) = count(DISTINCT observation_revision) "
              "AND count(*) = count(observation_revision) FROM octopus_core.proxy_events; "
            + migration
            + "ROLLBACK;")

    def test_populated_identity_upgrade_requires_explicit_maintenance(self):
        with self.assertRaisesRegex(RuntimeError, "requires reviewed"):
            self.migration_upgrade()

    def maintenance_settings(self, ceiling="100000", timeout="5s", window="10 minutes"):
        return (
            f"SET LOCAL statement_timeout = '{timeout}'; "
            f"SET LOCAL sslproxy.proxy_evidence_max_rows = '{ceiling}'; "
            "SELECT set_config('sslproxy.proxy_evidence_window_end', "
            f"(clock_timestamp() + interval '{window}')::text, true); ")

    def test_populated_identity_upgrade_rejects_unreviewed_growth(self):
        with self.assertRaisesRegex(RuntimeError, "exceed reviewed maintenance budget"):
            self.migration_upgrade(self.maintenance_settings(ceiling="1"))

    def test_populated_identity_upgrade_requires_finite_timeout_and_live_window(self):
        for timeout, window in (("0", "10 minutes"), ("5s", "-1 minute"), ("5s", "1 second")):
            with self.subTest(timeout=timeout, window=window):
                with self.assertRaisesRegex(RuntimeError, "finite statement_timeout"):
                    self.migration_upgrade(self.maintenance_settings(timeout=timeout, window=window))

    def test_reviewed_identity_upgrade_populates_unique_revisions_and_replays(self):
        self.assertEqual(self.migration_upgrade(self.maintenance_settings()).splitlines()[-1], "t")

    def test_empty_identity_install_needs_no_maintenance_window(self):
        self.assertEqual(self.migration_upgrade(empty=True), "t")

    def test_completed_identity_upgrade_does_not_lock_live_proxy_events(self):
        holder = subprocess.Popen(
            ["docker", "exec", "-i", self.container, "psql", "-X", "-qAt", "-U", "postgres",
             "-d", "sync", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            holder.stdin.write("BEGIN; LOCK TABLE octopus_core.proxy_events IN ROW EXCLUSIVE MODE; "
                               "SELECT 'locked';\n")
            holder.stdin.flush()
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            migration = (ROOT / "sql/postgres/octopus_core/01_tables/021_proxy_evidence.sql").read_text()
            self.sql("SET statement_timeout = '2s'; " + migration)
        finally:
            holder.stdin.write("ROLLBACK;\n")
            holder.stdin.flush()
            _, errors = holder.communicate(timeout=10)
            self.assertEqual(holder.returncode, 0, errors)


if __name__ == "__main__":
    unittest.main()
