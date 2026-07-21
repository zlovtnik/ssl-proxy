-- object: sync_errors
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_errors (
  id            BIGINT AUTO_INCREMENT NOT NULL,
  job_id        VARCHAR(36),
  batch_id      VARCHAR(36),
  error_class   VARCHAR(128),
  error_text    TEXT,
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  INDEX idx_sync_errors_job (job_id),
  INDEX idx_sync_errors_batch (batch_id)
);
