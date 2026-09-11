-- object: octopus_core_legacy_sinks_and_leases
-- depends_on: octopus_core_legacy_wireless_state
-- Legacy JDBC batch-sink tables (BatchSinkSql), lease/state tables
-- (MaintenanceSql, ProcessorStateSql), and compatibility columns for tables
-- whose canonical definition diverged (proxy_events, wireless_alerts,
-- outbox_events, processor_runs). Ported from the retired TiDB
-- 004_proxy_sink / 005_wireless_sink / 007_processor_leases_and_outbox /
-- 010_outbox_lease_lookup / 012_retention definitions to PostgreSQL.

CREATE TABLE IF NOT EXISTS octopus_core.wireless_sensors (
  sensor_pk     BIGSERIAL PRIMARY KEY,
  sensor_id     VARCHAR(64) NOT NULL,
  location_id   VARCHAR(128) NOT NULL,
  interface     VARCHAR(32) NOT NULL,
  reg_domain    VARCHAR(8) DEFAULT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT wireless_sensors_id_uq UNIQUE (sensor_id)
);

CREATE INDEX IF NOT EXISTS wireless_sensors_location_idx
  ON octopus_core.wireless_sensors (location_id);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_audit_frames (
  frame_pk          BIGSERIAL PRIMARY KEY,
  batch_id          VARCHAR(128) NOT NULL,
  row_sequence      INT NOT NULL,
  event_type        VARCHAR(64) NOT NULL,
  observed_at       timestamptz NOT NULL,
  sensor_id         VARCHAR(64) NOT NULL,
  location_id       VARCHAR(128) NOT NULL,
  interface         VARCHAR(32) NOT NULL,
  channel           SMALLINT NOT NULL,
  band              VARCHAR(8) NOT NULL,
  frame_type        VARCHAR(32) DEFAULT NULL,
  frame_subtype     VARCHAR(32) NOT NULL,
  bssid             VARCHAR(17) DEFAULT NULL,
  source_mac        VARCHAR(17) DEFAULT NULL,
  destination_mac   VARCHAR(17) DEFAULT NULL,
  transmitter_mac   VARCHAR(17) DEFAULT NULL,
  receiver_mac      VARCHAR(17) DEFAULT NULL,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  signal_dbm        SMALLINT DEFAULT NULL,
  sequence_number   INT DEFAULT NULL,
  raw_len           INT NOT NULL,
  is_retry          boolean NOT NULL DEFAULT false,
  is_more_data      boolean NOT NULL DEFAULT false,
  is_power_save     boolean NOT NULL DEFAULT false,
  is_protected      boolean NOT NULL DEFAULT false,
  is_to_ds          boolean NOT NULL DEFAULT false,
  is_from_ds        boolean NOT NULL DEFAULT false,
  is_handshake      boolean NOT NULL DEFAULT false,
  security_flags    INT NOT NULL DEFAULT 0,
  device_id         VARCHAR(128) DEFAULT NULL,
  username          VARCHAR(256) DEFAULT NULL,
  identity_source   VARCHAR(64) NOT NULL DEFAULT 'unknown',
  tags              VARCHAR(2000) DEFAULT NULL,
  anomaly_reasons   VARCHAR(1000) DEFAULT NULL,
  raw_json          jsonb DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT wireless_audit_frames_batch_uq UNIQUE (batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS wireless_audit_frames_sensor_idx
  ON octopus_core.wireless_audit_frames (sensor_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_location_idx
  ON octopus_core.wireless_audit_frames (location_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_source_idx
  ON octopus_core.wireless_audit_frames (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_bssid_idx
  ON octopus_core.wireless_audit_frames (bssid, observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_bandwidth_windows (
  bw_pk                BIGSERIAL PRIMARY KEY,
  batch_id             VARCHAR(128) NOT NULL,
  row_sequence         INT NOT NULL,
  schema_version       SMALLINT NOT NULL DEFAULT 1,
  window_start         timestamptz NOT NULL,
  window_end           timestamptz NOT NULL,
  sensor_id            VARCHAR(64) NOT NULL,
  location_id          VARCHAR(128) NOT NULL,
  interface            VARCHAR(32) NOT NULL,
  channel              SMALLINT NOT NULL,
  band                 VARCHAR(8) NOT NULL,
  source_mac           VARCHAR(17) NOT NULL,
  destination_bssid    VARCHAR(17) NOT NULL,
  ssid                 VARCHAR(256) DEFAULT NULL,
  bytes                BIGINT NOT NULL DEFAULT 0,
  frame_count          BIGINT NOT NULL DEFAULT 0,
  retry_count          BIGINT NOT NULL DEFAULT 0,
  more_data_count      BIGINT NOT NULL DEFAULT 0,
  power_save_count     BIGINT NOT NULL DEFAULT 0,
  strongest_signal_dbm SMALLINT DEFAULT NULL,
  hist_under_100       BIGINT NOT NULL DEFAULT 0,
  hist_100_500         BIGINT NOT NULL DEFAULT 0,
  hist_500_1000        BIGINT NOT NULL DEFAULT 0,
  hist_1000_1500       BIGINT NOT NULL DEFAULT 0,
  inter_arrival_p50_ms INT DEFAULT NULL,
  external_bssid       boolean NOT NULL DEFAULT false,
  threshold_exceeded   boolean NOT NULL DEFAULT false,
  wall_clock_delta_ms  BIGINT DEFAULT NULL,
  window_is_partial    boolean NOT NULL DEFAULT false,
  published_at         timestamptz DEFAULT NULL,
  created_at           timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT wireless_bandwidth_windows_batch_uq UNIQUE (batch_id, row_sequence),
  CONSTRAINT wireless_bandwidth_windows_range_ck CHECK (window_end >= window_start)
);

CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_sensor_idx
  ON octopus_core.wireless_bandwidth_windows (sensor_id, window_start);
CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_threshold_idx
  ON octopus_core.wireless_bandwidth_windows (threshold_exceeded, window_start);
CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_source_idx
  ON octopus_core.wireless_bandwidth_windows (source_mac, window_start);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_client_inventory (
  inventory_pk    BIGSERIAL PRIMARY KEY,
  sensor_id       VARCHAR(64) NOT NULL,
  location_id     VARCHAR(128) NOT NULL,
  snapshot_at     timestamptz NOT NULL,
  client_mac      VARCHAR(17) NOT NULL,
  bssid           VARCHAR(17) DEFAULT NULL,
  ssid            VARCHAR(256) DEFAULT NULL,
  device_id       VARCHAR(128) DEFAULT NULL,
  username        VARCHAR(256) DEFAULT NULL,
  identity_source VARCHAR(64) DEFAULT NULL,
  last_seen       timestamptz NOT NULL,
  first_seen      timestamptz NOT NULL,
  signal_dbm      SMALLINT DEFAULT NULL,
  is_authorized   boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT wireless_client_inventory_snapshot_uq UNIQUE (sensor_id, snapshot_at, client_mac)
);

CREATE INDEX IF NOT EXISTS wireless_client_inventory_mac_idx
  ON octopus_core.wireless_client_inventory (client_mac, snapshot_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_probe_requests (
  probe_pk     BIGSERIAL PRIMARY KEY,
  batch_id     VARCHAR(128) NOT NULL,
  row_sequence INT NOT NULL,
  client_mac   VARCHAR(17) NOT NULL,
  ssid         VARCHAR(256) NOT NULL,
  known_bssid  VARCHAR(17) DEFAULT NULL,
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  probe_count  INT NOT NULL DEFAULT 1,
  created_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT wireless_probe_requests_batch_uq UNIQUE (batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS wireless_probe_requests_mac_idx
  ON octopus_core.wireless_probe_requests (client_mac, last_seen);
CREATE INDEX IF NOT EXISTS wireless_probe_requests_ssid_idx
  ON octopus_core.wireless_probe_requests (ssid, last_seen);

CREATE TABLE IF NOT EXISTS octopus_core.proxy_blocked_host_rollups (
  id                 BIGSERIAL PRIMARY KEY,
  host               VARCHAR(253) NOT NULL,
  blocked_attempts   BIGINT NOT NULL DEFAULT 0,
  blocked_bytes      BIGINT NOT NULL DEFAULT 0,
  frequency_hz       DOUBLE PRECISION NOT NULL DEFAULT 0,
  verdict            VARCHAR(32) NOT NULL,
  category           VARCHAR(64) DEFAULT NULL,
  risk_score         DOUBLE PRECISION NOT NULL DEFAULT 0,
  tarpit_held_ms     BIGINT NOT NULL DEFAULT 0,
  iat_ms             BIGINT DEFAULT NULL,
  consecutive_blocks INT NOT NULL DEFAULT 0,
  last_verdict       VARCHAR(32) DEFAULT NULL,
  tls_ver            VARCHAR(16) DEFAULT NULL,
  alpn               VARCHAR(64) DEFAULT NULL,
  ja3_lite           VARCHAR(512) DEFAULT NULL,
  resolved_ip        VARCHAR(45) DEFAULT NULL,
  asn_org            VARCHAR(128) DEFAULT NULL,
  first_seen         timestamptz NOT NULL,
  updated_at         timestamptz NOT NULL,
  CONSTRAINT proxy_blocked_host_rollups_host_uq UNIQUE (host)
);

CREATE INDEX IF NOT EXISTS proxy_blocked_host_rollups_updated_idx
  ON octopus_core.proxy_blocked_host_rollups (updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.proxy_payload_audit (
  id                 BIGSERIAL PRIMARY KEY,
  correlation_id     VARCHAR(36) NOT NULL,
  host               VARCHAR(253) NOT NULL,
  direction          VARCHAR(4) NOT NULL,
  captured_at        timestamptz NOT NULL,
  byte_offset        INT NOT NULL DEFAULT 0,
  payload_object_key VARCHAR(1024) DEFAULT NULL,
  content_type       VARCHAR(128) DEFAULT NULL,
  http_method        VARCHAR(16) DEFAULT NULL,
  http_status        INT DEFAULT NULL,
  http_path          VARCHAR(2048) DEFAULT NULL,
  is_encrypted       boolean NOT NULL DEFAULT false,
  truncated          boolean NOT NULL DEFAULT false,
  peer_ip            VARCHAR(45) DEFAULT NULL,
  notes              VARCHAR(512) DEFAULT NULL,
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT proxy_payload_audit_capture_uq UNIQUE (correlation_id, direction, byte_offset),
  CONSTRAINT proxy_payload_audit_direction_ck CHECK (direction IN ('UP', 'DOWN'))
);

CREATE INDEX IF NOT EXISTS proxy_payload_audit_host_idx
  ON octopus_core.proxy_payload_audit (host, captured_at);

CREATE TABLE IF NOT EXISTS octopus_core.work_leases (
  resource_type    VARCHAR(64) NOT NULL,
  resource_id      VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      TEXT DEFAULT NULL,
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

CREATE INDEX IF NOT EXISTS work_leases_claim_idx
  ON octopus_core.work_leases (resource_type, next_attempt_at, lease_expires_at);

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

CREATE INDEX IF NOT EXISTS processor_state_status_idx
  ON octopus_core.processor_state (status, updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.retention_runs (
  run_id          TEXT NOT NULL,
  policy_name     VARCHAR(128) NOT NULL,
  target_table    VARCHAR(128) NOT NULL,
  cutoff_at       timestamptz NOT NULL,
  status          VARCHAR(32) NOT NULL,
  rows_selected   BIGINT NOT NULL DEFAULT 0,
  rows_archived   BIGINT NOT NULL DEFAULT 0,
  rows_deleted    BIGINT NOT NULL DEFAULT 0,
  lease_owner_id  VARCHAR(128) NOT NULL,
  lease_fence     BIGINT NOT NULL,
  error_text      TEXT DEFAULT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (run_id),
  CONSTRAINT retention_runs_status_ck CHECK (
    status IN ('running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT retention_runs_counts_ck CHECK (
    rows_selected >= 0 AND rows_archived >= 0 AND rows_deleted >= 0
  )
);

CREATE INDEX IF NOT EXISTS retention_runs_candidate_idx
  ON octopus_core.retention_runs (policy_name, status, started_at);

CREATE TABLE IF NOT EXISTS octopus_core.reconciliation_findings (
  finding_id         TEXT NOT NULL,
  processor_name     VARCHAR(128) NOT NULL,
  entity_type        VARCHAR(128) NOT NULL,
  entity_key         VARCHAR(255) NOT NULL,
  projection_version BIGINT NOT NULL DEFAULT 1,
  finding_type       VARCHAR(64) NOT NULL,
  expected_sha256    CHAR(64) DEFAULT NULL,
  actual_sha256      CHAR(64) DEFAULT NULL,
  status             VARCHAR(32) NOT NULL DEFAULT 'open',
  repair_action      VARCHAR(64) DEFAULT NULL,
  details            jsonb NOT NULL,
  first_seen_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at        timestamptz DEFAULT NULL,
  PRIMARY KEY (finding_id),
  CONSTRAINT reconciliation_findings_identity_uq UNIQUE (
    processor_name, entity_type, entity_key, projection_version, finding_type
  ),
  CONSTRAINT reconciliation_findings_status_ck CHECK (
    status IN ('open', 'repairing', 'resolved', 'ignored')
  )
);

CREATE INDEX IF NOT EXISTS reconciliation_findings_scan_idx
  ON octopus_core.reconciliation_findings (processor_name, status, last_seen_at);

CREATE TABLE IF NOT EXISTS octopus_core.outbox_publish_attempts (
  outbox_id    uuid NOT NULL,
  attempt_no   INT NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error_text   TEXT DEFAULT NULL,
  attempted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (outbox_id, attempt_no)
);

CREATE INDEX IF NOT EXISTS outbox_publish_attempts_time_idx
  ON octopus_core.outbox_publish_attempts (attempted_at);

-- Compatibility columns for tables whose canonical definition diverged
-- from the JDBC batch-sink contract. New-path columns already exist;
-- these ADD COLUMNs are idempotent across manifest reapplications.

ALTER TABLE octopus_core.proxy_events
  ADD COLUMN IF NOT EXISTS batch_id TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS row_sequence INT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS event_timestamp_utc timestamptz DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS wg_pubkey VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS device_id TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS identity_source TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS peer_hostname VARCHAR(253) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS client_ua VARCHAR(512) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS obfuscation_profile VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS parent_event_id BIGINT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS event_sequence INT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS duration_ms BIGINT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS reason VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS raw_json TEXT DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS proxy_events_batch_row_uq
  ON octopus_core.proxy_events (batch_id, row_sequence);

ALTER TABLE octopus_core.wireless_alerts
  ADD COLUMN IF NOT EXISTS batch_id VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS row_sequence INT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS alert_date DATE DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS location_id VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS interface VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS channel SMALLINT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS primary_mac VARCHAR(17) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS secondary_mac VARCHAR(17) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ssid VARCHAR(256) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS signal_dbm SMALLINT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS bytes BIGINT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS details_json jsonb DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS raw_json TEXT DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS wireless_alerts_batch_uq
  ON octopus_core.wireless_alerts (alert_type, batch_id, row_sequence);

CREATE UNIQUE INDEX IF NOT EXISTS outbox_events_topic_key_uq
  ON octopus_core.outbox_events (destination_topic, message_key);

CREATE INDEX IF NOT EXISTS outbox_events_lease_lookup_idx
  ON octopus_core.outbox_events (owner_id, lease_token);

ALTER TABLE octopus_core.processor_runs
  ADD COLUMN IF NOT EXISTS error_text TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS rows_reconciled BIGINT NOT NULL DEFAULT 0;
