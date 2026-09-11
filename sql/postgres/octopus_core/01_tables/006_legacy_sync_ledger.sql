-- object: octopus_core_legacy_sync_ledger
-- depends_on: octopus_core_wireless_sink
-- Legacy sync ledger tables used by the Octopus ingestion pipeline
-- (IngestionSql, JobBatchSql, ResultSql, MaintenanceSql). Ported from the
-- retired TiDB 002_sync_state / 003_ingestion_evidence definitions to
-- PostgreSQL. These coexist with the newer consumer_checkpoints,
-- ingestion_receipts, and work_items tables until the backend migrates.

CREATE TABLE IF NOT EXISTS octopus_core.sync_cursors (
  stream_name   VARCHAR(255) NOT NULL,
  cursor_value  TEXT NOT NULL,
  group_id      VARCHAR(128) DEFAULT NULL,
  group_version VARCHAR(64) DEFAULT NULL,
  artifact_sha256 CHAR(64) DEFAULT NULL,
  updated_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (stream_name)
);

CREATE TABLE IF NOT EXISTS octopus_core.consumer_offsets (
  group_id        VARCHAR(128) NOT NULL,
  topic           VARCHAR(255) NOT NULL,
  partition_id    INT NOT NULL,
  next_offset     BIGINT NOT NULL,
  group_version   VARCHAR(64) NOT NULL,
  artifact_sha256 CHAR(64) NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, topic, partition_id),
  CONSTRAINT consumer_offsets_partition_ck CHECK (partition_id >= 0),
  CONSTRAINT consumer_offsets_offset_ck CHECK (next_offset >= 0)
);

CREATE TABLE IF NOT EXISTS octopus_core.sync_jobs (
  job_id           TEXT NOT NULL,
  dedupe_key       VARCHAR(255) NOT NULL,
  stream_name      VARCHAR(255) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      TEXT DEFAULT NULL,
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

CREATE INDEX IF NOT EXISTS sync_jobs_claim_idx
  ON octopus_core.sync_jobs (status, next_attempt_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS sync_jobs_stream_idx
  ON octopus_core.sync_jobs (stream_name, status);

CREATE TABLE IF NOT EXISTS octopus_core.sync_batches (
  batch_id         TEXT NOT NULL,
  job_id           TEXT NOT NULL,
  batch_no         INT NOT NULL DEFAULT 0,
  payload_ref      TEXT NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  row_count        INT NOT NULL DEFAULT 1,
  checksum         CHAR(64) DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      TEXT DEFAULT NULL,
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

CREATE INDEX IF NOT EXISTS sync_batches_claim_idx
  ON octopus_core.sync_batches (status, next_attempt_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS sync_batches_outbox_idx
  ON octopus_core.sync_batches (outbox_id);

CREATE TABLE IF NOT EXISTS octopus_core.sync_errors (
  id          BIGSERIAL PRIMARY KEY,
  job_id      TEXT DEFAULT NULL,
  batch_id    TEXT DEFAULT NULL,
  error_class VARCHAR(128) NOT NULL,
  error_text  TEXT NOT NULL,
  retryable   boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS sync_errors_job_idx
  ON octopus_core.sync_errors (job_id, created_at);
CREATE INDEX IF NOT EXISTS sync_errors_batch_idx
  ON octopus_core.sync_errors (batch_id, created_at);

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

CREATE INDEX IF NOT EXISTS sync_backlog_claim_idx
  ON octopus_core.sync_backlog (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS octopus_core.ingestion_evidence (
  topic           VARCHAR(255) NOT NULL,
  partition_id    INT NOT NULL,
  record_offset   BIGINT NOT NULL,
  group_id        VARCHAR(128) NOT NULL,
  group_version   VARCHAR(64) NOT NULL,
  artifact_sha256 CHAR(64) NOT NULL,
  message_key     VARCHAR(512) DEFAULT NULL,
  payload_sha256  CHAR(64) NOT NULL,
  disposition     VARCHAR(32) NOT NULL DEFAULT 'received',
  dedupe_key      VARCHAR(255) DEFAULT NULL,
  first_seen_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ingestion_evidence_pkey PRIMARY KEY (group_id, topic, partition_id, record_offset),
  CONSTRAINT ingestion_evidence_disposition_ck CHECK (
    disposition IN ('received', 'duplicate', 'accepted', 'processed', 'rejected', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS ingestion_evidence_dedupe_idx
  ON octopus_core.ingestion_evidence (dedupe_key);
CREATE INDEX IF NOT EXISTS ingestion_evidence_disposition_idx
  ON octopus_core.ingestion_evidence (disposition, updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_events (
  dedupe_key              VARCHAR(255) NOT NULL,
  stream_name             VARCHAR(255) NOT NULL,
  observed_at             timestamptz NOT NULL,
  payload_ref             TEXT NOT NULL,
  payload                 jsonb DEFAULT NULL,
  payload_sha256          CHAR(64) DEFAULT NULL,
  status                  VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count           INT NOT NULL DEFAULT 0,
  last_error              TEXT DEFAULT NULL,
  producer                VARCHAR(128) NOT NULL DEFAULT 'unknown',
  event_kind              VARCHAR(64) DEFAULT NULL,
  payload_archive_uri     VARCHAR(2048) DEFAULT NULL,
  archived_payload_bytes  BIGINT DEFAULT NULL,
  payload_archived_at     timestamptz DEFAULT NULL,
  payload_archived        boolean NOT NULL DEFAULT false,
  sensor_id               VARCHAR(64) DEFAULT NULL,
  location_id             VARCHAR(128) DEFAULT NULL,
  username                VARCHAR(255) DEFAULT NULL,
  event_type              VARCHAR(64) DEFAULT NULL,
  schema_version          INT DEFAULT NULL,
  frame_type              VARCHAR(32) DEFAULT NULL,
  frame_subtype           VARCHAR(64) DEFAULT NULL,
  source_mac              VARCHAR(17) DEFAULT NULL,
  transmitter_mac         VARCHAR(17) DEFAULT NULL,
  receiver_mac            VARCHAR(17) DEFAULT NULL,
  bssid                   VARCHAR(17) DEFAULT NULL,
  destination_bssid       VARCHAR(17) DEFAULT NULL,
  ssid                    VARCHAR(256) DEFAULT NULL,
  signal_dbm              INT DEFAULT NULL,
  noise_dbm               INT DEFAULT NULL,
  frequency_mhz           INT DEFAULT NULL,
  channel_flags           INT DEFAULT NULL,
  data_rate_kbps          INT DEFAULT NULL,
  antenna_id              INT DEFAULT NULL,
  tsft                    BIGINT DEFAULT NULL,
  fragment_number         INT DEFAULT NULL,
  channel_number          INT DEFAULT NULL,
  signal_status           VARCHAR(64) DEFAULT NULL,
  adjacent_mac_hint       VARCHAR(512) DEFAULT NULL,
  qos_tid                 INT DEFAULT NULL,
  qos_eosp                boolean DEFAULT NULL,
  qos_ack_policy          INT DEFAULT NULL,
  qos_ack_policy_label    VARCHAR(64) DEFAULT NULL,
  qos_amsdu               boolean DEFAULT NULL,
  llc_oui                 VARCHAR(16) DEFAULT NULL,
  ethertype               INT DEFAULT NULL,
  ethertype_name          VARCHAR(64) DEFAULT NULL,
  src_ip                  VARCHAR(45) DEFAULT NULL,
  dst_ip                  VARCHAR(45) DEFAULT NULL,
  ip_ttl                  INT DEFAULT NULL,
  ip_protocol             INT DEFAULT NULL,
  ip_protocol_name        VARCHAR(64) DEFAULT NULL,
  src_port                INT DEFAULT NULL,
  dst_port                INT DEFAULT NULL,
  transport_protocol      VARCHAR(32) DEFAULT NULL,
  transport_length        INT DEFAULT NULL,
  transport_checksum      INT DEFAULT NULL,
  app_protocol            VARCHAR(64) DEFAULT NULL,
  ssdp_message_type       VARCHAR(64) DEFAULT NULL,
  ssdp_st                 VARCHAR(512) DEFAULT NULL,
  ssdp_mx                 VARCHAR(64) DEFAULT NULL,
  ssdp_usn                VARCHAR(512) DEFAULT NULL,
  dhcp_requested_ip       VARCHAR(45) DEFAULT NULL,
  dhcp_hostname           VARCHAR(253) DEFAULT NULL,
  dhcp_vendor_class       VARCHAR(255) DEFAULT NULL,
  dns_query_name          VARCHAR(253) DEFAULT NULL,
  mdns_name               VARCHAR(253) DEFAULT NULL,
  session_key             VARCHAR(255) DEFAULT NULL,
  retransmit_key          VARCHAR(255) DEFAULT NULL,
  frame_fingerprint       VARCHAR(255) DEFAULT NULL,
  payload_visibility      VARCHAR(64) DEFAULT NULL,
  tsft_delta_us           BIGINT DEFAULT NULL,
  wall_clock_delta_ms     BIGINT DEFAULT NULL,
  large_frame             boolean NOT NULL DEFAULT false,
  mixed_encryption        boolean DEFAULT NULL,
  dedupe_or_replay_suspect boolean NOT NULL DEFAULT false,
  raw_len                 INT NOT NULL DEFAULT 0,
  frame_control_flags     INT NOT NULL DEFAULT 0,
  more_data               boolean NOT NULL DEFAULT false,
  retry                   boolean NOT NULL DEFAULT false,
  power_save              boolean NOT NULL DEFAULT false,
  protected               boolean NOT NULL DEFAULT false,
  security_flags          INT NOT NULL DEFAULT 0,
  risk_score              DOUBLE PRECISION DEFAULT NULL,
  identity_source         VARCHAR(64) DEFAULT NULL,
  tags                    jsonb DEFAULT NULL,
  wps_device_name         VARCHAR(255) DEFAULT NULL,
  wps_manufacturer        VARCHAR(255) DEFAULT NULL,
  wps_model_name          VARCHAR(255) DEFAULT NULL,
  device_fingerprint      VARCHAR(255) DEFAULT NULL,
  handshake_captured      boolean NOT NULL DEFAULT false,
  wireless_search_text    TEXT DEFAULT NULL,
  created_at              timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at              timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name),
  CONSTRAINT sync_events_status_ck CHECK (
    status IN ('pending', 'processing', 'batched', 'completed', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS sync_events_status_idx
  ON octopus_core.sync_events (status, updated_at);
CREATE INDEX IF NOT EXISTS sync_events_stream_status_idx
  ON octopus_core.sync_events (stream_name, status, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_observed_idx
  ON octopus_core.sync_events (observed_at);
CREATE INDEX IF NOT EXISTS sync_events_sensor_observed_idx
  ON octopus_core.sync_events (sensor_id, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_source_observed_idx
  ON octopus_core.sync_events (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_bssid_observed_idx
  ON octopus_core.sync_events (bssid, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_location_observed_idx
  ON octopus_core.sync_events (location_id, observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_event_payload_archives (
  dedupe_key     VARCHAR(255) NOT NULL,
  stream_name    VARCHAR(255) NOT NULL,
  observed_at    timestamptz NOT NULL,
  payload_sha256 CHAR(64) DEFAULT NULL,
  archive_uri    VARCHAR(2048) NOT NULL,
  payload_bytes  BIGINT NOT NULL DEFAULT 0,
  archived_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name)
);

CREATE INDEX IF NOT EXISTS sync_event_archives_age_idx
  ON octopus_core.sync_event_payload_archives (archived_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_event_tombstones (
  dedupe_key     VARCHAR(255) NOT NULL,
  stream_name    VARCHAR(255) NOT NULL,
  payload_sha256 CHAR(64) DEFAULT NULL,
  observed_at    timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name)
);

CREATE INDEX IF NOT EXISTS sync_event_tombstones_expiry_idx
  ON octopus_core.sync_event_tombstones (expires_at);
