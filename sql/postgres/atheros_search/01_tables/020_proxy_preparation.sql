-- object: atheros_search_proxy_preparation
-- depends_on: atheros_search_wireless_stream_projection
-- Search receives a whitelist of noncredential evidence, never private source
-- rows, peer addresses, WireGuard keys, user agents or registration claims.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_event_evidence (
  event_id varchar(64) PRIMARY KEY,
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  observed_at timestamptz NOT NULL,
  host_normalized varchar(253),
  port integer CHECK (port BETWEEN 1 AND 65535),
  authority_normalized varchar(1024),
  registrable_domain varchar(253),
  normalization_version varchar(64) NOT NULL,
  parse_status varchar(32) NOT NULL,
  authority_source varchar(32) NOT NULL,
  sanitization_status varchar(32) NOT NULL,
  evidence_version varchar(64) NOT NULL,
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS proxy_event_evidence_host_time_idx
  ON atheros_search.proxy_event_evidence (host_normalized, observed_at, event_id);
CREATE INDEX IF NOT EXISTS proxy_event_evidence_retention_idx
  ON atheros_search.proxy_event_evidence (updated_at, event_id);

-- Current source pointers serialize supersession and identical-text metadata
-- corrections. Hash-derived source_version remains the legacy identity only.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_document_state (
  source_table varchar(128) NOT NULL,
  source_key varchar(255) NOT NULL,
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  document_id uuid,
  preparation_generation bigint NOT NULL CHECK (preparation_generation > 0),
  template_version varchar(64) NOT NULL,
  normalization_version varchar(64) NOT NULL,
  disposition varchar(32) NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (source_table, source_key)
);

-- Durable repair receipts keep the original error/attempt history intact.
CREATE TABLE IF NOT EXISTS atheros_search.embedding_repair_receipts (
  receipt_id uuid PRIMARY KEY,
  job_id uuid NOT NULL,
  previous_status varchar(32) NOT NULL,
  attempt_count integer NOT NULL,
  previous_error text,
  reason varchar(64) NOT NULL,
  repaired_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS atheros_search.embedding_repair_progress (
  campaign_id varchar(128) PRIMARY KEY,
  scope_sha256 char(64) NOT NULL,
  after_job_id uuid,
  scanned bigint NOT NULL DEFAULT 0,
  finished_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_preparation_policy (
  singleton boolean PRIMARY KEY CHECK (singleton),
  pending_high_water integer NOT NULL CHECK (pending_high_water > 0),
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE atheros_search.search_documents
  ADD COLUMN IF NOT EXISTS evidence_revision bigint,
  ADD COLUMN IF NOT EXISTS template_version varchar(64) NOT NULL DEFAULT 'legacy_unknown',
  ADD COLUMN IF NOT EXISTS normalization_version varchar(64) NOT NULL DEFAULT 'legacy_unknown',
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
-- Legacy substring host matching includes authority spellings such as :443.
-- Exact normalization lives in the evidence fields, not this compatibility key.
ALTER TABLE atheros_search.search_documents ALTER COLUMN host TYPE varchar(1024);
ALTER TABLE atheros_search.embedding_jobs
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE atheros_search.embeddings
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE atheros_search.search_vectors_event
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE atheros_search.search_vectors_device
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE atheros_search.search_vectors_behaviour
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE atheros_search.search_vectors_sequence
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown';

-- Compatible coexistence: changing the effective input does not overwrite a
-- different revision of the same document/model or any wireless vector.
ALTER TABLE atheros_search.embedding_jobs DROP CONSTRAINT IF EXISTS embedding_jobs_document_uq;
ALTER TABLE atheros_search.embedding_jobs ADD CONSTRAINT embedding_jobs_document_uq
  UNIQUE (document_id, embedding_kind, embedding_model, content_sha256, input_revision);
ALTER TABLE atheros_search.embeddings DROP CONSTRAINT IF EXISTS embeddings_document_kind_model_uq;
ALTER TABLE atheros_search.embeddings ADD CONSTRAINT embeddings_document_kind_model_uq
  UNIQUE (document_id, embedding_kind, embedding_model, input_revision);
ALTER TABLE atheros_search.search_vectors_event DROP CONSTRAINT IF EXISTS search_vectors_event_document_model_uq;
ALTER TABLE atheros_search.search_vectors_event ADD CONSTRAINT search_vectors_event_document_model_uq
  UNIQUE (document_id, embedding_model, input_revision);
ALTER TABLE atheros_search.search_vectors_device DROP CONSTRAINT IF EXISTS search_vectors_device_document_model_uq;
ALTER TABLE atheros_search.search_vectors_device ADD CONSTRAINT search_vectors_device_document_model_uq
  UNIQUE (document_id, embedding_model, input_revision);
ALTER TABLE atheros_search.search_vectors_behaviour DROP CONSTRAINT IF EXISTS search_vectors_behaviour_document_model_uq;
ALTER TABLE atheros_search.search_vectors_behaviour ADD CONSTRAINT search_vectors_behaviour_document_model_uq
  UNIQUE (document_id, embedding_model, input_revision);
ALTER TABLE atheros_search.search_vectors_sequence DROP CONSTRAINT IF EXISTS search_vectors_sequence_document_model_uq;
ALTER TABLE atheros_search.search_vectors_sequence ADD CONSTRAINT search_vectors_sequence_document_model_uq
  UNIQUE (document_id, embedding_model, input_revision);

ALTER TABLE atheros_search.similarity_scan_state
  ADD COLUMN IF NOT EXISTS scope varchar(16) NOT NULL DEFAULT 'wireless',
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown',
  ADD COLUMN IF NOT EXISTS normalization_version varchar(64) NOT NULL DEFAULT 'legacy_unknown',
  DROP CONSTRAINT IF EXISTS similarity_scan_state_pkey,
  ADD PRIMARY KEY (scope, input_revision, normalization_version, embedding_kind, vector_id);
ALTER TABLE atheros_search.similarity_pairs
  ADD COLUMN IF NOT EXISTS scope varchar(16) NOT NULL DEFAULT 'wireless',
  ADD COLUMN IF NOT EXISTS input_revision varchar(128) NOT NULL DEFAULT 'legacy_unknown',
  ADD COLUMN IF NOT EXISTS normalization_version varchar(64) NOT NULL DEFAULT 'legacy_unknown',
  DROP CONSTRAINT IF EXISTS similarity_pairs_documents_uq,
  ADD CONSTRAINT similarity_pairs_documents_uq UNIQUE
    (scope, input_revision, normalization_version, pair_kind, embedding_model, left_document_id, right_document_id);
