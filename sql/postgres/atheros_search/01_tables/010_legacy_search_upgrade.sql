-- object: atheros_search_legacy_search_upgrade
-- depends_on: atheros_search_embedding_recovery_contract
-- Preserve the per-kind vectors while populating the unified search surface.
-- Reconciliation must never overwrite a newer vector written by a worker.

INSERT INTO atheros_search.embeddings (
  document_id, embedding_kind, embedding_model, content_sha256,
  embedding, embedded_at, created_at
)
SELECT document_id, 'event', embedding_model, content_sha256,
       embedding, embedded_at, created_at
FROM atheros_search.search_vectors_event
UNION ALL
SELECT document_id, 'device', embedding_model, content_sha256,
       embedding, embedded_at, created_at
FROM atheros_search.search_vectors_device
UNION ALL
SELECT document_id, 'behaviour', embedding_model, content_sha256,
       embedding, embedded_at, created_at
FROM atheros_search.search_vectors_behaviour
UNION ALL
SELECT document_id, 'sequence', embedding_model, content_sha256,
       embedding, embedded_at, created_at
FROM atheros_search.search_vectors_sequence
ON CONFLICT (document_id, embedding_kind, embedding_model) DO NOTHING;

ALTER TABLE atheros_search.search_queries
  ADD COLUMN IF NOT EXISTS result_count INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS feedback VARCHAR(32),
  ADD COLUMN IF NOT EXISTS feedback_metadata jsonb;
