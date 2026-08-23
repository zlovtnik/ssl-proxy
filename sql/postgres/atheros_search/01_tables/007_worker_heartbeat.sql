-- object: atheros_search_worker_heartbeat
-- depends_on: atheros_search_search_vectors

CREATE TABLE IF NOT EXISTS atheros_search.worker_heartbeat (
  worker_id    VARCHAR(128) NOT NULL,
  worker_type  VARCHAR(64)  NOT NULL DEFAULT 'embedding',
  last_seen_at timestamptz  NOT NULL,
  metadata     jsonb,
  PRIMARY KEY (worker_id)
);

CREATE INDEX IF NOT EXISTS worker_heartbeat_type_idx ON atheros_search.worker_heartbeat (worker_type, last_seen_at);
