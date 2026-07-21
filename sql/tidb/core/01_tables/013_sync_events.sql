-- object: sync_events
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_events (
  dedupe_key    VARCHAR(255) NOT NULL,
  stream_name   VARCHAR(255) NOT NULL,
  observed_at   DATETIME(6) NOT NULL,
  payload_ref   TEXT,
  payload       JSON,
  payload_sha256 VARCHAR(64),
  status        VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count INT NOT NULL DEFAULT 0,
  last_error    TEXT,
  producer      VARCHAR(128),
  event_kind    VARCHAR(64),
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key, stream_name),
  INDEX idx_sync_events_status (status),
  INDEX idx_sync_events_stream_status (stream_name, status),
  INDEX idx_sync_events_observed (observed_at)
);
