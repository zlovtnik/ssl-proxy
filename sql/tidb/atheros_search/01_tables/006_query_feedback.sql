-- object: atheros_search_query_feedback
-- depends_on: atheros_search_graph_inventory_identity
-- Search query facts intentionally avoid foreign keys for write-path isolation.

USE atheros_search;

CREATE TABLE IF NOT EXISTS search_queries (
  query_id          BIGINT NOT NULL AUTO_INCREMENT,
  query_uuid        CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  query_text        TEXT DEFAULT NULL,
  hashed_query_text CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  query_kind        VARCHAR(32) NOT NULL,
  query_vector      VECTOR(768) DEFAULT NULL,
  top_k             INT NOT NULL DEFAULT 10,
  session_hash      CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  latency_ms        INT DEFAULT NULL,
  request_metadata  JSON DEFAULT NULL,
  created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at        DATETIME(6) NOT NULL,
  PRIMARY KEY (query_id),
  UNIQUE KEY search_queries_uuid_uq (query_uuid),
  KEY search_queries_created_idx (created_at),
  KEY search_queries_expires_idx (expires_at),
  KEY search_queries_hash_idx (hashed_query_text),
  CONSTRAINT search_queries_top_k_ck CHECK (top_k > 0),
  CONSTRAINT search_queries_latency_ck CHECK (latency_ms IS NULL OR latency_ms >= 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_query_results (
  query_id        BIGINT NOT NULL,
  ordinal         INT NOT NULL,
  document_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  result_key      VARCHAR(255) DEFAULT NULL,
  result_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  dense_score     DOUBLE DEFAULT NULL,
  sparse_score    DOUBLE DEFAULT NULL,
  rerank_score    DOUBLE DEFAULT NULL,
  final_score     DOUBLE DEFAULT NULL,
  result_metadata JSON DEFAULT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (query_id, ordinal),
  KEY search_query_results_hash_idx (result_key_hash),
  KEY search_query_results_document_idx (document_id),
  CONSTRAINT search_query_results_rank_ck CHECK (ordinal > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_feedback (
  feedback_id BIGINT NOT NULL AUTO_INCREMENT,
  id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  query_id    BIGINT NOT NULL,
  source_key  VARCHAR(255) NOT NULL,
  relevant    TINYINT(1) NOT NULL,
  feedback_type VARCHAR(32) NOT NULL DEFAULT 'relevance',
  actor_hash  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  metadata    JSON DEFAULT NULL,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (feedback_id),
  UNIQUE KEY search_feedback_id_uq (id),
  KEY search_feedback_query_idx (query_id, source_key),
  KEY search_feedback_created_idx (created_at)
) ENGINE=InnoDB;
