"""Exercise fresh and legacy schemas with an ephemeral pgvector Testcontainer.

Install scripts/requirements-test.txt to run this integration check.
"""

from __future__ import annotations

import unittest
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

    def test_fresh_install_and_legacy_upgrade_preserve_documents_and_vectors(self):
        self.sql("CREATE EXTENSION vector")
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


if __name__ == "__main__":
    unittest.main()
