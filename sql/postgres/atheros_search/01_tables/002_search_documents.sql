-- object: atheros_search_documents
-- depends_on: atheros_search_schema_manifest
-- Octopus writes normalized documents and postings. No PostgreSQL full-text index is
-- assumed; sparse ranking is implemented by the Go query facade.

CREATE TABLE IF NOT EXISTS atheros_search.search_documents (
  document_id       uuid NOT NULL,
  source_key        VARCHAR(255) NOT NULL,
  source_table      VARCHAR(128) NOT NULL,
  source_kind       VARCHAR(64) NOT NULL,
  source_version    BIGINT NOT NULL DEFAULT 1,
  source_mac        VARCHAR(17) DEFAULT NULL,
  location_id       VARCHAR(128) DEFAULT NULL,
  sensor_id         VARCHAR(64) DEFAULT NULL,
  observed_at       timestamptz DEFAULT NULL,
  bssid             VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  frame_subtype     VARCHAR(64) DEFAULT NULL,
  tags              jsonb NOT NULL,
  detail_json       jsonb NOT NULL,
  security_flags    INT NOT NULL DEFAULT 0,
  handshake_captured boolean NOT NULL DEFAULT false,
  title             VARCHAR(512) DEFAULT NULL,
  normalized_text   text NOT NULL,
  normalized_sha256 char(64) NOT NULL,
  locale            VARCHAR(16) NOT NULL DEFAULT 'und',
  status            VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata          jsonb NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (document_id),
  CONSTRAINT search_documents_source_uq UNIQUE (source_table, source_key, source_version),
  CONSTRAINT search_documents_status_ck CHECK (
    status IN ('active', 'superseded', 'deleted', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS search_documents_kind_observed_idx ON atheros_search.search_documents (source_kind, observed_at);
CREATE INDEX IF NOT EXISTS search_documents_mac_observed_idx ON atheros_search.search_documents (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS search_documents_location_observed_idx ON atheros_search.search_documents (location_id, observed_at);
CREATE INDEX IF NOT EXISTS search_documents_status_idx ON atheros_search.search_documents (status, updated_at);

CREATE TABLE IF NOT EXISTS atheros_search.search_document_tokens (
  token          VARCHAR(191) NOT NULL,
  document_id    uuid NOT NULL,
  field_name     VARCHAR(64) NOT NULL DEFAULT 'body',
  term_frequency double precision NOT NULL DEFAULT 1,
  token_count    INT NOT NULL DEFAULT 1,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (token, document_id, field_name),
  CONSTRAINT search_document_tokens_frequency_ck CHECK (term_frequency >= 0),
  CONSTRAINT search_document_tokens_count_ck CHECK (token_count > 0)
);

CREATE INDEX IF NOT EXISTS search_document_tokens_document_idx ON atheros_search.search_document_tokens (document_id);

CREATE TABLE IF NOT EXISTS atheros_search.search_document_tags (
  document_id uuid NOT NULL,
  tag_type    VARCHAR(64) NOT NULL,
  tag_value   VARCHAR(255) NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (document_id, tag_type, tag_value)
);

CREATE INDEX IF NOT EXISTS search_document_tags_lookup_idx ON atheros_search.search_document_tags (tag_type, tag_value, document_id);

CREATE TABLE IF NOT EXISTS atheros_search.search_filter_values (
  filter_kind      VARCHAR(64) NOT NULL,
  filter_value     VARCHAR(255) NOT NULL,
  normalized_value VARCHAR(255) NOT NULL,
  numeric_value    double precision DEFAULT NULL,
  datetime_value   timestamptz DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (filter_kind, normalized_value)
);

CREATE INDEX IF NOT EXISTS search_filter_values_number_idx ON atheros_search.search_filter_values (filter_kind, numeric_value);
CREATE INDEX IF NOT EXISTS search_filter_values_time_idx ON atheros_search.search_filter_values (filter_kind, datetime_value);

CREATE TABLE IF NOT EXISTS atheros_search.embedding_jobs (
  job_id           uuid NOT NULL,
  document_id      uuid NOT NULL,
  embedding_kind   VARCHAR(32) NOT NULL,
  embedding_model  VARCHAR(128) NOT NULL,
  content_sha256   char(64) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  priority         INT NOT NULL DEFAULT 100,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error       TEXT DEFAULT NULL,
  completed_at     timestamptz DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (job_id),
  CONSTRAINT embedding_jobs_document_uq UNIQUE (
    document_id, embedding_kind, embedding_model, content_sha256
  ),
  CONSTRAINT embedding_jobs_kind_ck CHECK (
    embedding_kind IN ('event', 'device', 'behaviour', 'sequence')
  ),
  CONSTRAINT embedding_jobs_status_ck CHECK (
    status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')
  )
);

CREATE INDEX IF NOT EXISTS embedding_jobs_claim_idx ON atheros_search.embedding_jobs (status, priority, next_attempt_at, lease_expires_at);
