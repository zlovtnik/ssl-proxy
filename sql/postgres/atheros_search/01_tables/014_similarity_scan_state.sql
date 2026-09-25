-- Durable progress for Octopus-owned vector similarity projections.
CREATE TABLE IF NOT EXISTS atheros_search.similarity_scan_state (
  embedding_kind VARCHAR(32) NOT NULL,
  vector_id BIGINT NOT NULL,
  embedded_at timestamptz NOT NULL,
  scan_started_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at timestamptz DEFAULT NULL,
  PRIMARY KEY (embedding_kind, vector_id)
);
