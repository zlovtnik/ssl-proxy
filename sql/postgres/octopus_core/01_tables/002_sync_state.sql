-- object: octopus_core_sync_state
-- depends_on: octopus_core_schema_control

CREATE TABLE IF NOT EXISTS octopus_core.sync_cursors (
  stream_name      VARCHAR(255) NOT NULL,
  cursor_value     TEXT NOT NULL,
  group_id         VARCHAR(128) DEFAULT NULL,
  group_version    VARCHAR(64) DEFAULT NULL,
  artifact_sha256  char(64) DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (stream_name)
);

CREATE TABLE IF NOT EXISTS octopus_core.cutover_offset_sets (
  offset_set_id    uuid NOT NULL,
  group_version    VARCHAR(64) NOT NULL,
  captured_at      timestamptz NOT NULL,
  captured_by      VARCHAR(128) NOT NULL,
  artifact_sha256  char(64) NOT NULL,
  activated_at     timestamptz DEFAULT NULL,
  activated_by     VARCHAR(128) DEFAULT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'captured',
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (offset_set_id),
  CONSTRAINT cutover_offset_sets_version_uq UNIQUE (group_version),
  CONSTRAINT cutover_offset_sets_status_ck CHECK (
    status IN ('captured', 'verified', 'activated', 'retired')
  )
);

CREATE TABLE IF NOT EXISTS octopus_core.cutover_offsets (
  offset_set_id uuid NOT NULL,
  topic         VARCHAR(255) NOT NULL,
  partition_id  INT NOT NULL,
  end_offset    BIGINT NOT NULL,
  group_id       VARCHAR(128) NOT NULL,
  initialized_at timestamptz DEFAULT NULL,
  verified_at    timestamptz DEFAULT NULL,
  PRIMARY KEY (group_id, topic, partition_id)
);

CREATE INDEX IF NOT EXISTS cutover_offsets_set_idx ON octopus_core.cutover_offsets (offset_set_id);

CREATE TABLE IF NOT EXISTS octopus_core.consumer_offsets (
  group_id         VARCHAR(128) NOT NULL,
  topic            VARCHAR(255) NOT NULL,
  partition_id     INT NOT NULL,
  next_offset      BIGINT NOT NULL,
  group_version    VARCHAR(64) NOT NULL,
  artifact_sha256  char(64) NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, topic, partition_id)
);

CREATE TABLE IF NOT EXISTS octopus_core.sync_jobs (
  job_id           uuid NOT NULL,
  dedupe_key       VARCHAR(255) NOT NULL,
  stream_name      VARCHAR(255) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  last_error       TEXT DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at       timestamptz DEFAULT NULL,
  finished_at      timestamptz DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (job_id),
  CONSTRAINT sync_jobs_event_uq UNIQUE (dedupe_key, stream_name),
  CONSTRAINT sync_jobs_status_ck CHECK (
    status IN ('pending', 'leased', 'running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT sync_jobs_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
);

CREATE INDEX IF NOT EXISTS sync_jobs_claim_idx ON octopus_core.sync_jobs (status, next_attempt_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS sync_jobs_stream_idx ON octopus_core.sync_jobs (stream_name, status);

CREATE TABLE IF NOT EXISTS octopus_core.sync_batches (
  batch_id         uuid NOT NULL,
  job_id           uuid NOT NULL,
  batch_no         INT NOT NULL DEFAULT 0,
  payload_ref      TEXT NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  row_count        INT NOT NULL DEFAULT 1,
  checksum         char(64) DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  last_error       TEXT DEFAULT NULL,
  dedupe_key       VARCHAR(255) NOT NULL,
  stream_name      VARCHAR(255) NOT NULL,
  cursor_start     VARCHAR(255) NOT NULL,
  cursor_end       VARCHAR(255) NOT NULL,
  outbox_id        uuid DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (batch_id),
  CONSTRAINT sync_batches_event_uq UNIQUE (dedupe_key, stream_name),
  CONSTRAINT sync_batches_job_no_uq UNIQUE (job_id, batch_no),
  CONSTRAINT sync_batches_status_ck CHECK (
    status IN ('pending', 'leased', 'processing', 'dispatched', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT sync_batches_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
);

CREATE INDEX IF NOT EXISTS sync_batches_claim_idx ON octopus_core.sync_batches (status, next_attempt_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS sync_batches_outbox_idx ON octopus_core.sync_batches (outbox_id);

CREATE TABLE IF NOT EXISTS octopus_core.sync_errors (
  id          bigserial,
  job_id      uuid DEFAULT NULL,
  batch_id    uuid DEFAULT NULL,
  error_class VARCHAR(128) NOT NULL,
  error_text  TEXT NOT NULL,
  retryable   boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS sync_errors_job_idx ON octopus_core.sync_errors (job_id, created_at);
CREATE INDEX IF NOT EXISTS sync_errors_batch_idx ON octopus_core.sync_errors (batch_id, created_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_backlog (
  dedupe_key      VARCHAR(255) NOT NULL,
  stream_name     VARCHAR(255) NOT NULL,
  payload         jsonb NOT NULL,
  failure_stage   VARCHAR(32) NOT NULL DEFAULT 'pre_publish',
  status          VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count   INT NOT NULL DEFAULT 0,
  max_attempts    INT NOT NULL DEFAULT 5,
  next_attempt_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error      TEXT DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name),
  CONSTRAINT sync_backlog_stage_ck CHECK (
    failure_stage IN ('pre_publish', 'post_publish')
  ),
  CONSTRAINT sync_backlog_status_ck CHECK (
    status IN ('pending', 'leased', 'synced', 'sync_failed', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS sync_backlog_claim_idx ON octopus_core.sync_backlog (status, next_attempt_at);
