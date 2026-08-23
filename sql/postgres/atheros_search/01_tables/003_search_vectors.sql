-- object: atheros_search_vectors
-- depends_on: atheros_search_documents
-- HNSW indexes are intentionally absent here. Apply post_tiflash only after
-- each table reports AVAILABLE=1 in INFORMATION_SCHEMA.TIFLASH_REPLICA.

CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_event (
  vector_id       bigserial,
  document_id     uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  char(64) NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (vector_id),
  CONSTRAINT search_vectors_event_document_uq UNIQUE (document_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS search_vectors_event_embedded_idx ON atheros_search.search_vectors_event (embedded_at);

CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_device (
  vector_id       bigserial,
  document_id     uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  char(64) NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (vector_id),
  CONSTRAINT search_vectors_device_document_uq UNIQUE (document_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS search_vectors_device_embedded_idx ON atheros_search.search_vectors_device (embedded_at);

CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_behaviour (
  vector_id       bigserial,
  document_id     uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  char(64) NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (vector_id),
  CONSTRAINT search_vectors_behaviour_document_uq UNIQUE (document_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS search_vectors_behaviour_embedded_idx ON atheros_search.search_vectors_behaviour (embedded_at);

CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_sequence (
  vector_id       bigserial,
  document_id     uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  char(64) NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (vector_id),
  CONSTRAINT search_vectors_sequence_document_uq UNIQUE (document_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS search_vectors_sequence_embedded_idx ON atheros_search.search_vectors_sequence (embedded_at);

CREATE INDEX IF NOT EXISTS search_vectors_event_hnsw_idx
  ON atheros_search.search_vectors_event USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_device_hnsw_idx
  ON atheros_search.search_vectors_device USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_behaviour_hnsw_idx
  ON atheros_search.search_vectors_behaviour USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_sequence_hnsw_idx
  ON atheros_search.search_vectors_sequence USING hnsw (embedding vector_cosine_ops);
