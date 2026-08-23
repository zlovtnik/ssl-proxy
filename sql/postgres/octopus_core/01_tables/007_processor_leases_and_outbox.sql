-- object: octopus_core_processor_leases_and_outbox
-- depends_on: octopus_core_sync_state
-- Claims are conditional UPDATEs checked by affected-row count. A worker may
-- mutate a claimed resource only while owner_id, lease_token, and fence match.

CREATE TABLE IF NOT EXISTS octopus_core.work_leases (
  resource_type    VARCHAR(64) NOT NULL,
  resource_id      VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  fence            BIGINT NOT NULL DEFAULT 0,
  attempt_count    INT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error       TEXT DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (resource_type, resource_id),
  CONSTRAINT work_leases_attempt_count_ck CHECK (attempt_count >= 0),
  CONSTRAINT work_leases_owner_token_ck CHECK (
    (owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (owner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS work_leases_claim_idx ON octopus_core.work_leases (resource_type, next_attempt_at, lease_expires_at);

CREATE TABLE IF NOT EXISTS octopus_core.processor_state (
  processor_name       VARCHAR(128) NOT NULL,
  shard_id             VARCHAR(128) NOT NULL DEFAULT 'default',
  status               VARCHAR(32) NOT NULL DEFAULT 'idle',
  checkpoint_value     TEXT DEFAULT NULL,
  last_started_at      timestamptz DEFAULT NULL,
  last_succeeded_at    timestamptz DEFAULT NULL,
  last_failed_at       timestamptz DEFAULT NULL,
  rows_processed       BIGINT NOT NULL DEFAULT 0,
  consecutive_failures INT NOT NULL DEFAULT 0,
  last_error           TEXT DEFAULT NULL,
  updated_at           timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (processor_name, shard_id),
  CONSTRAINT processor_state_status_ck CHECK (
    status IN ('idle', 'running', 'degraded', 'failed', 'disabled')
  )
);

CREATE INDEX IF NOT EXISTS processor_state_status_idx ON octopus_core.processor_state (status, updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.processor_runs (
  run_id          uuid NOT NULL,
  processor_name  VARCHAR(128) NOT NULL,
  shard_id        VARCHAR(128) NOT NULL DEFAULT 'default',
  status          VARCHAR(32) NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz DEFAULT NULL,
  rows_read       BIGINT NOT NULL DEFAULT 0,
  rows_written    BIGINT NOT NULL DEFAULT 0,
  rows_reconciled BIGINT NOT NULL DEFAULT 0,
  error_class     VARCHAR(128) DEFAULT NULL,
  error_text      TEXT DEFAULT NULL,
  PRIMARY KEY (run_id)
);

CREATE INDEX IF NOT EXISTS processor_runs_name_idx ON octopus_core.processor_runs (processor_name, started_at);
CREATE INDEX IF NOT EXISTS processor_runs_status_idx ON octopus_core.processor_runs (status, started_at);

CREATE TABLE IF NOT EXISTS octopus_core.outbox_events (
  outbox_id         uuid NOT NULL,
  source_type       VARCHAR(64) NOT NULL,
  source_id         VARCHAR(255) NOT NULL,
  event_type        VARCHAR(128) NOT NULL,
  destination_topic VARCHAR(255) NOT NULL,
  message_key       VARCHAR(255) NOT NULL,
  payload           jsonb NOT NULL,
  headers           jsonb DEFAULT NULL,
  status            VARCHAR(32) NOT NULL DEFAULT 'pending',
  owner_id          VARCHAR(128) DEFAULT NULL,
  lease_token       uuid DEFAULT NULL,
  fence             BIGINT NOT NULL DEFAULT 0,
  attempt_count     INT NOT NULL DEFAULT 0,
  max_attempts      INT NOT NULL DEFAULT 10,
  lease_expires_at  timestamptz DEFAULT NULL,
  next_attempt_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error        TEXT DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at      timestamptz DEFAULT NULL,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (outbox_id),
  CONSTRAINT outbox_events_topic_key_uq UNIQUE (destination_topic, message_key),
  CONSTRAINT outbox_events_status_ck CHECK (
    status IN ('pending', 'leased', 'published', 'failed', 'cancelled')
  ),
  CONSTRAINT outbox_events_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
);

CREATE INDEX IF NOT EXISTS outbox_events_claim_idx ON octopus_core.outbox_events (status, next_attempt_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS outbox_events_source_idx ON octopus_core.outbox_events (source_type, source_id);

CREATE TABLE IF NOT EXISTS octopus_core.outbox_publish_attempts (
  outbox_id    uuid NOT NULL,
  attempt_no   INT NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error_text   TEXT DEFAULT NULL,
  attempted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (outbox_id, attempt_no)
);

CREATE INDEX IF NOT EXISTS outbox_publish_attempts_time_idx ON octopus_core.outbox_publish_attempts (attempted_at);

CREATE TABLE IF NOT EXISTS octopus_core.retention_policies (
  policy_name       VARCHAR(128) NOT NULL,
  target_table      VARCHAR(128) NOT NULL,
  retention_days    INT NOT NULL,
  archive_required  boolean NOT NULL DEFAULT false,
  enabled           boolean NOT NULL DEFAULT true,
  last_completed_at timestamptz DEFAULT NULL,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (policy_name),
  CONSTRAINT retention_policies_days_ck CHECK (retention_days > 0)
);
