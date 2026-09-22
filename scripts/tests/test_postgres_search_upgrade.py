"""Exercise fresh and legacy schemas with an ephemeral pgvector Testcontainer.

Install scripts/requirements-test.txt to run this integration check.
"""

from __future__ import annotations

import unittest
import time
from pathlib import Path

import yaml

try:
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy
except ImportError:
    DockerContainer = None


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "sql/postgres/atheros_search"


@unittest.skipIf(DockerContainer is None, "install scripts/requirements-test.txt")
class PostgresSearchUpgradeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.postgres = (
            DockerContainer("pgvector/pgvector:0.8.6-pg16-bookworm")
            .with_env("POSTGRES_PASSWORD", "integration-test")
            .with_env("POSTGRES_DB", "sync")
            .waiting_for(LogMessageWaitStrategy("database system is ready to accept connections", times=2))
        )
        cls.postgres.start()
        cls.addClassCleanup(cls.postgres.stop)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready = cls.postgres.exec([
                "psql", "-X", "-U", "postgres", "-d", "sync", "-Atc", "SELECT 1",
            ])
            if ready.exit_code == 0 and ready.output.decode().strip() == "1":
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("ephemeral PostgreSQL did not become query-ready")

    def sql(self, query):
        result = self.postgres.exec([
            "psql", "-X", "-U", "postgres", "-d", "sync", "-At",
            "-v", "ON_ERROR_STOP=1", "-c", query,
        ])
        self.assertEqual(result.exit_code, 0, result.output.decode())
        return result.output.decode().strip()

    def apply_manifest(self):
        manifest = yaml.safe_load((SCHEMA / "manifest.yaml").read_text())
        for relative in manifest["apply_order"]:
            with self.subTest(migration=relative):
                self.sql((SCHEMA / relative).read_text())

    def reset_schema(self):
        self.sql("DROP SCHEMA IF EXISTS atheros_search CASCADE; CREATE EXTENSION IF NOT EXISTS vector")

    def test_fresh_install_and_legacy_upgrade_preserve_documents_and_vectors(self):
        self.reset_schema()
        self.apply_manifest()
        self.assertEqual(self.sql("SELECT count(*) FROM atheros_search.schema_readiness"), "1")

        # Reproduce the September 10 schema: per-kind vectors and source_key,
        # without the new readiness relation, full-text columns or query count.
        self.sql("""
            DROP TABLE atheros_search.schema_readiness;
            DROP TABLE atheros_search.embeddings;
            ALTER TABLE atheros_search.search_documents
              DROP COLUMN source_id, DROP COLUMN search_vector, DROP COLUMN filters;
            ALTER TABLE atheros_search.search_queries
              DROP COLUMN result_count, DROP COLUMN feedback, DROP COLUMN feedback_metadata;
        """)
        kinds = {"event": "event", "device": "device",
                 "behaviour": "behaviour_window", "sequence": "frame_sequence"}
        for number, (kind, source_kind) in enumerate(kinds.items(), start=1):
            self.sql(f"""
                INSERT INTO atheros_search.search_documents (
                  document_id, source_key, source_table, source_kind,
                  normalized_text, normalized_sha256, tags
                ) VALUES (
                  '00000000-0000-0000-0000-{number:012d}', 'legacy-{kind}', '{kind}',
                  '{source_kind}', 'legacy wireless evidence', repeat('a',64), '["wifi"]'
                );
                INSERT INTO atheros_search.search_vectors_{kind} (
                  document_id, embedding_model, content_sha256, embedding, embedded_at
                ) VALUES (
                  '00000000-0000-0000-0000-{number:012d}', 'test-model', repeat('a',64),
                  array_fill(0.1::real, ARRAY[768])::vector, CURRENT_TIMESTAMP
                );
            """)

        self.apply_manifest()
        self.assertEqual(self.sql("""
            SELECT count(*) FROM atheros_search.search_documents
            WHERE source_id = source_key
              AND search_vector @@ to_tsquery('simple', 'wireless')
              AND filters -> 'tags' = '["wifi"]'::jsonb
        """), "4")
        self.assertEqual(self.sql("SELECT count(*) FROM atheros_search.embeddings"), "4")

        # A reconciliation must not duplicate vectors or overwrite worker output.
        self.sql("UPDATE atheros_search.embeddings SET content_sha256 = repeat('b',64)")
        self.apply_manifest()
        self.assertEqual(self.sql("""
            SELECT count(*) FROM atheros_search.embeddings
            WHERE content_sha256 = repeat('b',64)
        """), "4")
        self.assertEqual(self.sql("SELECT count(*) FROM atheros_search.search_vectors_event"), "1")
        self.sql("""
            INSERT INTO atheros_search.search_queries (
              query_uuid, hashed_query_text, query_kind, result_count, expires_at
            ) VALUES (gen_random_uuid(), repeat('a',64), 'hybrid', 4, CURRENT_TIMESTAMP)
        """)

    def test_retired_identity_graph_shape_is_upgraded_without_losing_rows(self):
        self.reset_schema()
        self.sql("""
            CREATE SCHEMA atheros_search;
            CREATE TABLE atheros_search.merge_candidates (
              candidate_id uuid PRIMARY KEY,
              mac_a varchar(17) NOT NULL,
              mac_b varchar(17) NOT NULL,
              confidence double precision NOT NULL,
              computed_at timestamptz NOT NULL,
              status varchar(32) NOT NULL DEFAULT 'pending',
              evidence jsonb,
              expires_at timestamptz,
              projection_run_id uuid,
              created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
              CONSTRAINT merge_candidates_pair_uq UNIQUE (mac_a, mac_b)
            );
            CREATE INDEX merge_candidates_status_idx
              ON atheros_search.merge_candidates (status, confidence);
            CREATE TABLE atheros_search.merge_decisions (
              decision_id uuid PRIMARY KEY,
              candidate_id uuid NOT NULL UNIQUE,
              decision varchar(32) NOT NULL,
              decided_at timestamptz NOT NULL
            );
            CREATE TABLE atheros_search.identity_clusters (
              cluster_id uuid PRIMARY KEY,
              cluster_name varchar(255),
              cluster_size int NOT NULL DEFAULT 1,
              first_seen timestamptz NOT NULL,
              last_seen timestamptz NOT NULL,
              status varchar(32) NOT NULL DEFAULT 'active',
              projection_run_id uuid,
              updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE atheros_search.identity_cluster_members (
              cluster_id uuid NOT NULL,
              mac varchar(17) NOT NULL UNIQUE,
              confidence double precision NOT NULL DEFAULT 1,
              evidence jsonb,
              first_seen timestamptz NOT NULL,
              last_seen timestamptz NOT NULL,
              updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (cluster_id, mac)
            );
            CREATE TABLE atheros_search.graph_nodes (
              node_id varchar(255) PRIMARY KEY,
              node_kind varchar(32) NOT NULL,
              node_payload jsonb NOT NULL,
              observed_at timestamptz NOT NULL,
              projection_run_id uuid,
              updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE atheros_search.graph_edges (
              edge_id varchar(255) PRIMARY KEY,
              source_node_id varchar(255) NOT NULL,
              target_node_id varchar(255) NOT NULL,
              edge_kind varchar(64) NOT NULL,
              weight double precision NOT NULL DEFAULT 1,
              evidence jsonb,
              projection_run_id uuid,
              updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.merge_candidates (
              candidate_id, mac_a, mac_b, confidence, computed_at
            ) VALUES (
              '00000000-0000-0000-0000-000000000001',
              '00:00:00:00:00:01', '00:00:00:00:00:02', 0.8, CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.merge_decisions (
              decision_id, candidate_id, decision, decided_at
            ) VALUES (
              '00000000-0000-0000-0000-000000000002',
              '00000000-0000-0000-0000-000000000001', 'merge', CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.merge_decisions (
              decision_id, candidate_id, decision, decided_at
            ) VALUES (
              '00000000-0000-0000-0000-000000000004',
              '00000000-0000-0000-0000-000000000005', 'merge', CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.identity_clusters (
              cluster_id, cluster_name, first_seen, last_seen
            ) VALUES (
              '00000000-0000-0000-0000-000000000003', 'legacy',
              CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.identity_cluster_members (
              cluster_id, mac, first_seen, last_seen
            ) VALUES (
              '00000000-0000-0000-0000-000000000003', '00:00:00:00:00:01',
              CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            );
            INSERT INTO atheros_search.graph_nodes (
              node_id, node_kind, node_payload, observed_at
            ) VALUES ('legacy-node', 'device', '{}', CURRENT_TIMESTAMP);
            INSERT INTO atheros_search.graph_edges (
              edge_id, source_node_id, target_node_id, edge_kind
            ) VALUES ('legacy-edge', 'legacy-node', 'legacy-node', 'identity_member');
        """)

        self.apply_manifest()

        self.assertEqual(self.sql("""
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name IN ('merge_candidates', 'merge_decisions', 'identity_clusters',
                                 'identity_cluster_members', 'graph_nodes', 'graph_edges')
              AND column_name IN ('candidate_id', 'cluster_id', 'node_id', 'edge_id',
                                  'source_node_id', 'target_node_id', 'projection_run_id')
              AND data_type IN ('text', 'character varying')
        """), "12")
        self.assertEqual(self.sql("""
            SELECT count(*)
            FROM atheros_search.merge_candidates
            WHERE evidence = '{}'::jsonb AND projection_run_id = candidate_id
        """), "1")
        self.assertEqual(self.sql("""
            SELECT count(*)
            FROM atheros_search.graph_edges
            WHERE evidence = '{}'::jsonb AND projection_run_id = edge_id
        """), "1")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM pg_constraint
            WHERE conrelid = 'atheros_search.merge_decisions'::regclass
              AND conname = 'merge_decisions_fk' AND convalidated AND confdeltype = 'c'
        """), "1")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM pg_constraint
            WHERE conrelid = 'atheros_search.merge_decisions'::regclass
              AND contype = 'p'
              AND pg_get_constraintdef(oid) = 'PRIMARY KEY (candidate_id)'
        """), "1")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name = 'merge_decisions'
              AND column_name = 'decision_id'
        """), "0")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name = 'merge_decisions'
              AND column_name = 'decided_at'
              AND column_default IS NOT NULL
        """), "1")
        self.assertEqual(self.sql("SELECT count(*) FROM atheros_search.merge_decisions"), "1")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name = 'graph_nodes'
              AND column_name IN ('label', 'location_id', 'sensor_id', 'normalized_mac',
                                  'normalized_ssid', 'is_threat')
        """), "6")
        self.assertEqual(self.sql("""
            SELECT character_maximum_length FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name = 'graph_nodes' AND column_name = 'node_kind'
        """), "64")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND table_name = 'graph_edges'
              AND column_name IN ('label', 'observed_at')
        """), "2")
        self.assertEqual(self.sql("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'atheros_search'
              AND is_nullable = 'YES'
              AND (
                (table_name = 'identity_clusters' AND column_name IN ('first_seen', 'last_seen'))
                OR (table_name = 'identity_cluster_members' AND column_name IN ('first_seen', 'last_seen'))
                OR (table_name = 'graph_nodes' AND column_name = 'observed_at')
              )
        """), "5")
        self.assertIn("computed_at", self.sql("""
            SELECT indexdef FROM pg_indexes
            WHERE schemaname = 'atheros_search'
              AND indexname = 'merge_candidates_status_idx'
        """))

        # Direct replay remains SQL-safe, while the executor ledger prevents it
        # from doing this work during normal reconciliation.
        self.apply_manifest()
        self.assertEqual(self.sql("SELECT count(*) FROM atheros_search.merge_candidates"), "1")


if __name__ == "__main__":
    unittest.main()
