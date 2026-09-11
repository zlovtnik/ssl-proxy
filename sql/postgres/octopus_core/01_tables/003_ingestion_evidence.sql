-- object: octopus_core_ingestion_work_and_failures
-- depends_on: octopus_core_configuration_and_checkpoints

CREATE TABLE IF NOT EXISTS octopus_core.ingestion_receipts (
  consumer_group  VARCHAR(128) NOT NULL,
  topic           VARCHAR(255) NOT NULL,
  partition_id    INT NOT NULL,
  record_offset   BIGINT NOT NULL,
  event_id        VARCHAR(255) NOT NULL,
  payload_sha256  char(64) NOT NULL,
  artifact_sha256 char(64) NOT NULL,
  schema_version  INT DEFAULT NULL,
  disposition     VARCHAR(32) NOT NULL DEFAULT 'received',
  received_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at    timestamptz DEFAULT NULL,
  PRIMARY KEY (consumer_group, topic, partition_id, record_offset),
  CONSTRAINT ingestion_receipts_event_uq UNIQUE (topic, event_id),
  CONSTRAINT ingestion_receipts_partition_ck CHECK (partition_id >= 0),
  CONSTRAINT ingestion_receipts_offset_ck CHECK (record_offset >= 0),
  CONSTRAINT ingestion_receipts_disposition_ck CHECK (
    disposition IN ('received', 'processing', 'processed', 'rejected', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS ingestion_receipts_event_idx
  ON octopus_core.ingestion_receipts (event_id, topic);
CREATE INDEX IF NOT EXISTS ingestion_receipts_disposition_idx
  ON octopus_core.ingestion_receipts (disposition, received_at);

CREATE TABLE IF NOT EXISTS octopus_core.work_items (
  work_id           uuid NOT NULL,
  work_kind         VARCHAR(32) NOT NULL,
  dedupe_key        VARCHAR(255) NOT NULL,
  source_receipt    jsonb DEFAULT NULL,
  payload           jsonb NOT NULL,
  status            VARCHAR(32) NOT NULL DEFAULT 'pending',
  priority          INT NOT NULL DEFAULT 100,
  owner_id          VARCHAR(128) DEFAULT NULL,
  lease_token       uuid DEFAULT NULL,
  lease_fence       BIGINT NOT NULL DEFAULT 0,
  lease_expires_at  timestamptz DEFAULT NULL,
  attempt_count     INT NOT NULL DEFAULT 0,
  max_attempts      INT NOT NULL DEFAULT 5,
  next_attempt_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error        TEXT DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at        timestamptz DEFAULT NULL,
  finished_at       timestamptz DEFAULT NULL,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (work_id),
  CONSTRAINT work_items_dedupe_uq UNIQUE (work_kind, dedupe_key),
  CONSTRAINT work_items_kind_ck CHECK (work_kind IN ('job', 'batch', 'backlog', 'maintenance')),
  CONSTRAINT work_items_status_ck CHECK (
    status IN ('pending', 'leased', 'running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT work_items_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  ),
  CONSTRAINT work_items_lease_ck CHECK (
    (status IN ('leased', 'running') AND owner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR
    (status NOT IN ('leased', 'running') AND owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT work_items_payload_ck CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS work_items_claim_idx
  ON octopus_core.work_items (priority, next_attempt_at, work_id)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS octopus_core.dead_letters (
  dead_letter_id   uuid NOT NULL,
  topic            VARCHAR(255) NOT NULL,
  partition_id     INT DEFAULT NULL,
  record_offset    BIGINT DEFAULT NULL,
  event_id_hash    char(64) DEFAULT NULL,
  payload_sha256   char(64) DEFAULT NULL,
  error_class      VARCHAR(128) NOT NULL,
  sanitized_error TEXT NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'parked',
  replay_count     INT NOT NULL DEFAULT 0,
  next_replay_at   timestamptz DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dead_letter_id),
  CONSTRAINT dead_letters_status_ck CHECK (status IN ('parked', 'replay_pending', 'replayed', 'discarded')),
  CONSTRAINT dead_letters_replay_count_ck CHECK (replay_count >= 0)
);

CREATE INDEX IF NOT EXISTS dead_letters_replay_idx
  ON octopus_core.dead_letters (status, next_replay_at);
