-- object: octopus_core_outbox_and_processors
-- depends_on: octopus_core_ingestion_work_and_failures

CREATE TABLE IF NOT EXISTS octopus_core.outbox_events (
  outbox_id          uuid NOT NULL,
  source_type        VARCHAR(64) NOT NULL,
  source_id          VARCHAR(255) NOT NULL,
  event_type         VARCHAR(128) NOT NULL,
  destination_topic  VARCHAR(255) NOT NULL,
  message_key        VARCHAR(255) NOT NULL,
  payload            jsonb NOT NULL,
  headers            jsonb NOT NULL DEFAULT '{}'::jsonb,
  status             VARCHAR(32) NOT NULL DEFAULT 'pending',
  owner_id           VARCHAR(128) DEFAULT NULL,
  lease_token        uuid DEFAULT NULL,
  fence              BIGINT NOT NULL DEFAULT 0,
  attempt_count      INT NOT NULL DEFAULT 0,
  max_attempts       INT NOT NULL DEFAULT 10,
  lease_expires_at   timestamptz DEFAULT NULL,
  next_attempt_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error         TEXT DEFAULT NULL,
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at       timestamptz DEFAULT NULL,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (outbox_id),
  CONSTRAINT outbox_events_source_event_uq UNIQUE (source_type, source_id, event_type),
  CONSTRAINT outbox_events_status_ck CHECK (
    status IN ('pending', 'leased', 'published', 'failed', 'cancelled')
  ),
  CONSTRAINT outbox_events_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  ),
  CONSTRAINT outbox_events_payload_ck CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT outbox_events_headers_ck CHECK (jsonb_typeof(headers) = 'object')
);

CREATE INDEX IF NOT EXISTS outbox_events_claim_idx
  ON octopus_core.outbox_events (next_attempt_at, outbox_id)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS octopus_core.outbox_attempts (
  outbox_id       uuid NOT NULL,
  attempt_no      INT NOT NULL,
  status          VARCHAR(32) NOT NULL,
  sanitized_error TEXT DEFAULT NULL,
  attempted_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (outbox_id, attempt_no),
  CONSTRAINT outbox_attempts_no_ck CHECK (attempt_no > 0),
  CONSTRAINT outbox_attempts_status_ck CHECK (status IN ('published', 'retryable_failure', 'failed'))
);

CREATE TABLE IF NOT EXISTS octopus_core.processor_runs (
  run_id          uuid NOT NULL,
  processor_name  VARCHAR(128) NOT NULL,
  shard_id        VARCHAR(128) NOT NULL DEFAULT 'default',
  status          VARCHAR(32) NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz DEFAULT NULL,
  rows_read       BIGINT NOT NULL DEFAULT 0,
  rows_written    BIGINT NOT NULL DEFAULT 0,
  error_class     VARCHAR(128) DEFAULT NULL,
  sanitized_error TEXT DEFAULT NULL,
  PRIMARY KEY (run_id),
  CONSTRAINT processor_runs_status_ck CHECK (
    status IN ('running', 'completed', 'retrying', 'failed_terminal', 'failed', 'cancelled')
  )
);

CREATE INDEX IF NOT EXISTS processor_runs_name_idx
  ON octopus_core.processor_runs (processor_name, started_at DESC);

CREATE TABLE IF NOT EXISTS octopus_core.processor_checkpoints (
  processor_name       VARCHAR(128) NOT NULL,
  shard_id             VARCHAR(128) NOT NULL DEFAULT 'default',
  checkpoint_value     TEXT DEFAULT NULL,
  status               VARCHAR(32) NOT NULL DEFAULT 'waiting_for_source',
  last_started_at      timestamptz DEFAULT NULL,
  last_succeeded_at    timestamptz DEFAULT NULL,
  last_failed_at       timestamptz DEFAULT NULL,
  rows_processed       BIGINT NOT NULL DEFAULT 0,
  consecutive_failures INT NOT NULL DEFAULT 0,
  sanitized_error      TEXT DEFAULT NULL,
  updated_at           timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (processor_name, shard_id),
  CONSTRAINT processor_checkpoints_status_ck CHECK (
    status IN ('waiting_for_source', 'running', 'healthy', 'degraded', 'failed', 'disabled')
  )
);
