-- object: atheros_search_queries_and_workers
-- depends_on: atheros_search_embeddings

CREATE TABLE IF NOT EXISTS atheros_search.search_queries (
  query_id          bigserial,
  query_uuid        uuid NOT NULL,
  hashed_query_text char(64) NOT NULL,
  query_kind        VARCHAR(32) NOT NULL,
  top_k             INT NOT NULL DEFAULT 10,
  session_hash      char(64) DEFAULT NULL,
  latency_ms        INT DEFAULT NULL,
  result_count      INT NOT NULL DEFAULT 0,
  request_metadata  jsonb NOT NULL DEFAULT '{}'::jsonb,
  feedback          VARCHAR(32) DEFAULT NULL,
  feedback_metadata jsonb DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at        timestamptz NOT NULL,
  PRIMARY KEY (query_id),
  CONSTRAINT search_queries_uuid_uq UNIQUE (query_uuid),
  CONSTRAINT search_queries_top_k_ck CHECK (top_k > 0),
  CONSTRAINT search_queries_latency_ck CHECK (latency_ms IS NULL OR latency_ms >= 0),
  CONSTRAINT search_queries_result_count_ck CHECK (result_count >= 0),
  CONSTRAINT search_queries_metadata_object_ck CHECK (jsonb_typeof(request_metadata) = 'object'),
  CONSTRAINT search_queries_feedback_ck CHECK (feedback IS NULL OR feedback IN ('helpful', 'not_helpful'))
);

CREATE INDEX IF NOT EXISTS search_queries_expires_idx ON atheros_search.search_queries (expires_at);
CREATE INDEX IF NOT EXISTS search_queries_created_idx ON atheros_search.search_queries (created_at DESC);

CREATE TABLE IF NOT EXISTS atheros_search.worker_heartbeat (
  worker_id    VARCHAR(128) NOT NULL,
  worker_type  VARCHAR(64) NOT NULL DEFAULT 'embedding',
  last_seen_at timestamptz NOT NULL,
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (worker_id),
  CONSTRAINT worker_heartbeat_metadata_object_ck CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS worker_heartbeat_type_idx
  ON atheros_search.worker_heartbeat (worker_type, last_seen_at DESC);
