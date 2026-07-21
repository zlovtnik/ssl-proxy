-- object: sync_event_tombstones
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_event_tombstones (
  dedupe_key    VARCHAR(255) NOT NULL,
  stream_name   VARCHAR(255) NOT NULL,
  expires_at    DATETIME(6) NOT NULL,
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key, stream_name)
);
