-- object: sync_batches
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_batches (
  batch_id      VARCHAR(36) NOT NULL,
  job_id        VARCHAR(36) NOT NULL,
  batch_no      INT NOT NULL DEFAULT 0,
  payload_ref   TEXT,
  status        VARCHAR(32) NOT NULL DEFAULT 'pending',
  row_count     INT NOT NULL DEFAULT 1,
  checksum      VARCHAR(64),
  attempt_count INT NOT NULL DEFAULT 0,
  last_error    TEXT,
  dedupe_key    VARCHAR(255),
  stream_name   VARCHAR(255),
  cursor_start  VARCHAR(64),
  cursor_end    VARCHAR(64),
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (batch_id),
  INDEX idx_sync_batches_status (status),
  INDEX idx_sync_batches_job (job_id),
  INDEX idx_sync_batches_dedupe (dedupe_key, stream_name),
  INDEX idx_sync_batches_updated (updated_at)
);
