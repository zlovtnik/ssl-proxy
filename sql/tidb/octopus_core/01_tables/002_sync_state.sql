-- object: octopus_core_sync_state
-- depends_on: octopus_core_schema_control

USE octopus_core;

CREATE TABLE IF NOT EXISTS sync_cursors (
  stream_name      VARCHAR(255) NOT NULL,
  cursor_value     TEXT NOT NULL,
  group_id         VARCHAR(128) DEFAULT NULL,
  group_version    VARCHAR(64) DEFAULT NULL,
  artifact_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (stream_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cutover_offset_sets (
  offset_set_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  group_version    VARCHAR(64) NOT NULL,
  captured_at      DATETIME(6) NOT NULL,
  captured_by      VARCHAR(128) NOT NULL,
  artifact_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  activated_at     DATETIME(6) DEFAULT NULL,
  activated_by     VARCHAR(128) DEFAULT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'captured',
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (offset_set_id),
  UNIQUE KEY cutover_offset_sets_version_uq (group_version),
  CONSTRAINT cutover_offset_sets_status_ck CHECK (
    status IN ('captured', 'verified', 'activated', 'retired')
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cutover_offsets (
  offset_set_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  topic         VARCHAR(255) NOT NULL,
  partition_id  INT NOT NULL,
  end_offset    BIGINT NOT NULL,
  group_id       VARCHAR(128) NOT NULL,
  initialized_at DATETIME(6) DEFAULT NULL,
  verified_at    DATETIME(6) DEFAULT NULL,
  PRIMARY KEY (group_id, topic, partition_id),
  KEY cutover_offsets_set_idx (offset_set_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS consumer_offsets (
  group_id         VARCHAR(128) NOT NULL,
  topic            VARCHAR(255) NOT NULL,
  partition_id     INT NOT NULL,
  next_offset      BIGINT NOT NULL,
  group_version    VARCHAR(64) NOT NULL,
  artifact_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (group_id, topic, partition_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_jobs (
  job_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  dedupe_key       VARCHAR(255) NOT NULL,
  stream_name      VARCHAR(255) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  last_error       TEXT DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  started_at       DATETIME(6) DEFAULT NULL,
  finished_at      DATETIME(6) DEFAULT NULL,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (job_id),
  UNIQUE KEY sync_jobs_event_uq (dedupe_key, stream_name),
  KEY sync_jobs_claim_idx (status, next_attempt_at, lease_expires_at),
  KEY sync_jobs_stream_idx (stream_name, status),
  CONSTRAINT sync_jobs_status_ck CHECK (
    status IN ('pending', 'leased', 'running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT sync_jobs_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_batches (
  batch_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  batch_no         INT NOT NULL DEFAULT 0,
  payload_ref      TEXT NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  row_count        INT NOT NULL DEFAULT 1,
  checksum         CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  last_error       TEXT DEFAULT NULL,
  dedupe_key       VARCHAR(255) NOT NULL,
  stream_name      VARCHAR(255) NOT NULL,
  cursor_start     VARCHAR(255) NOT NULL,
  cursor_end       VARCHAR(255) NOT NULL,
  outbox_id        CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (batch_id),
  UNIQUE KEY sync_batches_event_uq (dedupe_key, stream_name),
  UNIQUE KEY sync_batches_job_no_uq (job_id, batch_no),
  KEY sync_batches_claim_idx (status, next_attempt_at, lease_expires_at),
  KEY sync_batches_outbox_idx (outbox_id),
  CONSTRAINT sync_batches_status_ck CHECK (
    status IN ('pending', 'leased', 'processing', 'dispatched', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT sync_batches_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_errors (
  id          BIGINT NOT NULL AUTO_INCREMENT,
  job_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  batch_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  error_class VARCHAR(128) NOT NULL,
  error_text  TEXT NOT NULL,
  retryable   TINYINT(1) NOT NULL DEFAULT 0,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY sync_errors_job_idx (job_id, created_at),
  KEY sync_errors_batch_idx (batch_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_backlog (
  dedupe_key      VARCHAR(255) NOT NULL,
  stream_name     VARCHAR(255) NOT NULL,
  payload         JSON NOT NULL,
  failure_stage   VARCHAR(32) NOT NULL DEFAULT 'pre_publish',
  status          VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count   INT NOT NULL DEFAULT 0,
  max_attempts    INT NOT NULL DEFAULT 5,
  next_attempt_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_error      TEXT DEFAULT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key, stream_name),
  KEY sync_backlog_claim_idx (status, next_attempt_at),
  CONSTRAINT sync_backlog_stage_ck CHECK (
    failure_stage IN ('pre_publish', 'post_publish')
  ),
  CONSTRAINT sync_backlog_status_ck CHECK (
    status IN ('pending', 'leased', 'synced', 'sync_failed', 'failed')
  )
) ENGINE=InnoDB;
