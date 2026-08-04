-- object: atheros_search_documents
-- depends_on: atheros_search_schema_manifest
-- Octopus writes normalized documents and postings. No TiDB full-text index is
-- assumed; sparse ranking is implemented by the Go query facade.

USE atheros_search;

CREATE TABLE IF NOT EXISTS search_documents (
  document_id       CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_key        VARCHAR(255) NOT NULL,
  source_table      VARCHAR(128) NOT NULL,
  source_kind       VARCHAR(64) NOT NULL,
  source_version    BIGINT NOT NULL DEFAULT 1,
  source_mac        VARCHAR(17) DEFAULT NULL,
  location_id       VARCHAR(128) DEFAULT NULL,
  sensor_id         VARCHAR(64) DEFAULT NULL,
  observed_at       DATETIME(6) DEFAULT NULL,
  bssid             VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  frame_subtype     VARCHAR(64) DEFAULT NULL,
  tags              JSON NOT NULL,
  detail_json       JSON NOT NULL,
  security_flags    INT NOT NULL DEFAULT 0,
  handshake_captured TINYINT(1) NOT NULL DEFAULT 0,
  title             VARCHAR(512) DEFAULT NULL,
  normalized_text   LONGTEXT NOT NULL,
  normalized_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  locale            VARCHAR(16) NOT NULL DEFAULT 'und',
  status            VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata          JSON NOT NULL,
  created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (document_id),
  UNIQUE KEY search_documents_source_uq (source_table, source_key, source_version),
  KEY search_documents_kind_observed_idx (source_kind, observed_at),
  KEY search_documents_mac_observed_idx (source_mac, observed_at),
  KEY search_documents_location_observed_idx (location_id, observed_at),
  KEY search_documents_status_idx (status, updated_at),
  CONSTRAINT search_documents_status_ck CHECK (
    status IN ('active', 'superseded', 'deleted', 'failed')
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_document_tokens (
  token          VARCHAR(191) NOT NULL,
  document_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  field_name     VARCHAR(64) NOT NULL DEFAULT 'body',
  term_frequency DOUBLE NOT NULL DEFAULT 1,
  token_count    INT NOT NULL DEFAULT 1,
  updated_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (token, document_id, field_name),
  KEY search_document_tokens_document_idx (document_id),
  CONSTRAINT search_document_tokens_frequency_ck CHECK (term_frequency >= 0),
  CONSTRAINT search_document_tokens_count_ck CHECK (token_count > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_document_tags (
  document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  tag_type    VARCHAR(64) NOT NULL,
  tag_value   VARCHAR(255) NOT NULL,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (document_id, tag_type, tag_value),
  KEY search_document_tags_lookup_idx (tag_type, tag_value, document_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_filter_values (
  filter_kind      VARCHAR(64) NOT NULL,
  filter_value     VARCHAR(255) NOT NULL,
  normalized_value VARCHAR(255) NOT NULL,
  numeric_value    DOUBLE DEFAULT NULL,
  datetime_value   DATETIME(6) DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (filter_kind, normalized_value),
  KEY search_filter_values_number_idx (filter_kind, numeric_value),
  KEY search_filter_values_time_idx (filter_kind, datetime_value)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS embedding_jobs (
  job_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  document_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding_kind   VARCHAR(32) NOT NULL,
  embedding_model  VARCHAR(128) NOT NULL,
  content_sha256   CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  priority         INT NOT NULL DEFAULT 100,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_error       TEXT DEFAULT NULL,
  completed_at     DATETIME(6) DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (job_id),
  UNIQUE KEY embedding_jobs_document_uq (
    document_id, embedding_kind, embedding_model, content_sha256
  ),
  KEY embedding_jobs_claim_idx (status, priority, next_attempt_at, lease_expires_at),
  CONSTRAINT embedding_jobs_kind_ck CHECK (
    embedding_kind IN ('event', 'device', 'behaviour', 'sequence')
  ),
  CONSTRAINT embedding_jobs_status_ck CHECK (
    status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')
  )
) ENGINE=InnoDB;
