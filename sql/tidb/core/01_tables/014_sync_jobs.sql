-- object: sync_jobs
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_jobs (
  job_id        VARCHAR(36) NOT NULL,
  stream_name   VARCHAR(255) NOT NULL,
  status        VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count INT NOT NULL DEFAULT 0,
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  started_at    DATETIME(6),
  finished_at   DATETIME(6),
  PRIMARY KEY (job_id),
  INDEX idx_sync_jobs_status (status),
  INDEX idx_sync_jobs_stream (stream_name)
);
