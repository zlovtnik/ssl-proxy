-- object: atheros_search_embedding_recovery_contract
-- depends_on: atheros_search_projection_maintenance
-- Append-only compatibility contract for Octopus document preparation and the
-- four durable embedding kinds. pgvector is intentionally installed in public.

DO $$
BEGIN
  IF to_regtype('public.vector') IS NULL THEN
    RAISE EXCEPTION 'pgvector extension must be installed in public before atheros_search schema migration';
  END IF;
END $$;

ALTER TABLE atheros_search.search_documents
  ADD COLUMN IF NOT EXISTS source_key VARCHAR(255),
  ADD COLUMN IF NOT EXISTS source_table VARCHAR(128),
  ADD COLUMN IF NOT EXISTS tags jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS locale VARCHAR(16) NOT NULL DEFAULT 'und',
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE atheros_search.search_documents
SET source_key = source_id,
    source_table = CASE source_kind
      WHEN 'event' THEN 'wireless_frames'
      WHEN 'device' THEN 'inventory_devices'
      ELSE 'legacy'
    END
WHERE source_key IS NULL OR source_table IS NULL;

ALTER TABLE atheros_search.search_documents
  ALTER COLUMN source_key SET NOT NULL,
  ALTER COLUMN source_table SET NOT NULL,
  ALTER COLUMN search_vector SET DEFAULT ''::tsvector;

ALTER TABLE atheros_search.search_documents
  DROP CONSTRAINT IF EXISTS search_documents_kind_ck;
ALTER TABLE atheros_search.search_documents
  ADD CONSTRAINT search_documents_kind_ck CHECK (
    source_kind IN ('event', 'device', 'behaviour_window', 'frame_sequence')
  );
ALTER TABLE atheros_search.search_documents
  DROP CONSTRAINT IF EXISTS search_documents_tags_array_ck,
  DROP CONSTRAINT IF EXISTS search_documents_metadata_object_ck;
ALTER TABLE atheros_search.search_documents
  ADD CONSTRAINT search_documents_tags_array_ck CHECK (jsonb_typeof(tags) = 'array'),
  ADD CONSTRAINT search_documents_metadata_object_ck CHECK (jsonb_typeof(metadata) = 'object');

CREATE UNIQUE INDEX IF NOT EXISTS search_documents_source_table_key_version_uq
  ON atheros_search.search_documents (source_table, source_key, source_version);
CREATE INDEX IF NOT EXISTS search_documents_kind_active_idx
  ON atheros_search.search_documents (source_kind, observed_at, document_id)
  WHERE status = 'active';

ALTER TABLE atheros_search.embedding_jobs
  DROP CONSTRAINT IF EXISTS embedding_jobs_kind_ck;
ALTER TABLE atheros_search.embedding_jobs
  ADD CONSTRAINT embedding_jobs_kind_ck CHECK (
    embedding_kind IN ('event', 'device', 'behaviour', 'sequence')
  );

ALTER TABLE atheros_search.embeddings
  ALTER COLUMN embedding TYPE public.vector(768) USING embedding::public.vector;
ALTER TABLE atheros_search.embeddings
  DROP CONSTRAINT IF EXISTS embeddings_kind_ck;
ALTER TABLE atheros_search.embeddings
  ADD CONSTRAINT embeddings_kind_ck CHECK (
    embedding_kind IN ('event', 'device', 'behaviour', 'sequence')
  );

CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_event (
  vector_id bigserial PRIMARY KEY,
  document_id uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  embedding public.vector(768) NOT NULL,
  embedded_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT search_vectors_event_document_model_uq UNIQUE (document_id, embedding_model)
);
CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_device (
  vector_id bigserial PRIMARY KEY,
  document_id uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  embedding public.vector(768) NOT NULL,
  embedded_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT search_vectors_device_document_model_uq UNIQUE (document_id, embedding_model)
);
CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_behaviour (
  vector_id bigserial PRIMARY KEY,
  document_id uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  embedding public.vector(768) NOT NULL,
  embedded_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT search_vectors_behaviour_document_model_uq UNIQUE (document_id, embedding_model)
);
CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_sequence (
  vector_id bigserial PRIMARY KEY,
  document_id uuid NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  embedding public.vector(768) NOT NULL,
  embedded_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT search_vectors_sequence_document_model_uq UNIQUE (document_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS search_vectors_event_embedding_hnsw_idx
  ON atheros_search.search_vectors_event USING hnsw (embedding public.vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_device_embedding_hnsw_idx
  ON atheros_search.search_vectors_device USING hnsw (embedding public.vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_behaviour_embedding_hnsw_idx
  ON atheros_search.search_vectors_behaviour USING hnsw (embedding public.vector_cosine_ops);
CREATE INDEX IF NOT EXISTS search_vectors_sequence_embedding_hnsw_idx
  ON atheros_search.search_vectors_sequence USING hnsw (embedding public.vector_cosine_ops);

CREATE TABLE IF NOT EXISTS atheros_search.search_document_tokens (
  document_id uuid NOT NULL,
  token VARCHAR(255) NOT NULL,
  field_name VARCHAR(64) NOT NULL,
  term_frequency double precision NOT NULL,
  token_count INT NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (document_id, token, field_name),
  CONSTRAINT search_document_tokens_count_ck CHECK (token_count > 0)
);
CREATE INDEX IF NOT EXISTS search_document_tokens_token_idx
  ON atheros_search.search_document_tokens (token, document_id);

CREATE TABLE IF NOT EXISTS atheros_search.search_document_tags (
  document_id uuid NOT NULL,
  tag_type VARCHAR(64) NOT NULL,
  tag_value VARCHAR(255) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (document_id, tag_type, tag_value)
);
CREATE INDEX IF NOT EXISTS search_document_tags_lookup_idx
  ON atheros_search.search_document_tags (tag_type, tag_value, document_id);
