-- object: atheros_search_embeddings
-- depends_on: atheros_search_documents_jobs_devices

CREATE TABLE IF NOT EXISTS atheros_search.embeddings (
  embedding_id    bigserial,
  document_id     uuid NOT NULL,
  embedding_kind  VARCHAR(32) NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  char(64) NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (embedding_id),
  CONSTRAINT embeddings_document_kind_model_uq UNIQUE (
    document_id, embedding_kind, embedding_model
  ),
  CONSTRAINT embeddings_kind_ck CHECK (embedding_kind IN ('event', 'device'))
);

CREATE INDEX IF NOT EXISTS embeddings_kind_model_idx
  ON atheros_search.embeddings (embedding_kind, embedding_model, embedded_at DESC);
CREATE INDEX IF NOT EXISTS embeddings_hnsw_idx
  ON atheros_search.embeddings USING hnsw (embedding vector_cosine_ops);
