-- object: atheros_search_query_feedback
-- depends_on: atheros_search_graph_inventory_identity
-- Search query facts intentionally avoid foreign keys for write-path isolation.

CREATE TABLE IF NOT EXISTS atheros_search.search_queries (
  query_id          bigserial,
  query_uuid        uuid NOT NULL,
  query_text        TEXT DEFAULT NULL,
  hashed_query_text char(64) NOT NULL,
  query_kind        VARCHAR(32) NOT NULL,
  query_vector      VECTOR(768) DEFAULT NULL,
  top_k             INT NOT NULL DEFAULT 10,
  session_hash      char(64) DEFAULT NULL,
  latency_ms        INT DEFAULT NULL,
  request_metadata  jsonb DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at        timestamptz NOT NULL,
  PRIMARY KEY (query_id),
  CONSTRAINT search_queries_uuid_uq UNIQUE (query_uuid),
  CONSTRAINT search_queries_top_k_ck CHECK (top_k > 0),
  CONSTRAINT search_queries_latency_ck CHECK (latency_ms IS NULL OR latency_ms >= 0)
);

CREATE INDEX IF NOT EXISTS search_queries_created_idx ON atheros_search.search_queries (created_at);
CREATE INDEX IF NOT EXISTS search_queries_expires_idx ON atheros_search.search_queries (expires_at);
CREATE INDEX IF NOT EXISTS search_queries_hash_idx ON atheros_search.search_queries (hashed_query_text);

CREATE TABLE IF NOT EXISTS atheros_search.search_query_results (
  query_id        BIGINT NOT NULL,
  ordinal         INT NOT NULL,
  document_id     uuid DEFAULT NULL,
  result_key      VARCHAR(255) DEFAULT NULL,
  result_key_hash char(64) NOT NULL,
  dense_score     double precision DEFAULT NULL,
  sparse_score    double precision DEFAULT NULL,
  rerank_score    double precision DEFAULT NULL,
  final_score     double precision DEFAULT NULL,
  result_metadata jsonb DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (query_id, ordinal),
  CONSTRAINT search_query_results_rank_ck CHECK (ordinal > 0)
);

CREATE INDEX IF NOT EXISTS search_query_results_hash_idx ON atheros_search.search_query_results (result_key_hash);
CREATE INDEX IF NOT EXISTS search_query_results_document_idx ON atheros_search.search_query_results (document_id);

CREATE TABLE IF NOT EXISTS atheros_search.search_feedback (
  feedback_id bigserial,
  id          uuid DEFAULT NULL,
  query_id    BIGINT NOT NULL,
  source_key  VARCHAR(255) NOT NULL,
  relevant    boolean NOT NULL,
  feedback_type VARCHAR(32) NOT NULL DEFAULT 'relevance',
  actor_hash  char(64) DEFAULT NULL,
  metadata    jsonb DEFAULT NULL,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (feedback_id),
  CONSTRAINT search_feedback_id_uq UNIQUE (id)
);

CREATE INDEX IF NOT EXISTS search_feedback_query_idx ON atheros_search.search_feedback (query_id, source_key);
CREATE INDEX IF NOT EXISTS search_feedback_created_idx ON atheros_search.search_feedback (created_at);
