-- object: octopus_core_wireless_sink
-- depends_on: octopus_core_ingestion_evidence
-- These columns preserve the current Octopus sink contract.
-- High-volume facts deliberately have no foreign keys.

CREATE TABLE IF NOT EXISTS octopus_core.wireless_sensors (
  sensor_pk     bigserial,
  sensor_id     VARCHAR(64) NOT NULL,
  location_id   VARCHAR(128) NOT NULL,
  interface     VARCHAR(32) NOT NULL,
  reg_domain    VARCHAR(8) DEFAULT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (sensor_pk),
  CONSTRAINT wireless_sensors_id_uq UNIQUE (sensor_id)
);

CREATE INDEX IF NOT EXISTS wireless_sensors_location_idx ON octopus_core.wireless_sensors (location_id);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_audit_frames (
  frame_pk          bigserial,
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
  PRIMARY KEY (frame_pk),
  CONSTRAINT wireless_audit_frames_batch_uq UNIQUE (batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS wireless_audit_frames_sensor_idx ON octopus_core.wireless_audit_frames (sensor_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_location_idx ON octopus_core.wireless_audit_frames (location_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_source_idx ON octopus_core.wireless_audit_frames (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS wireless_audit_frames_bssid_idx ON octopus_core.wireless_audit_frames (bssid, observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_bandwidth_windows (
  bw_pk                bigserial,
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
  PRIMARY KEY (bw_pk),
  CONSTRAINT wireless_bandwidth_windows_batch_uq UNIQUE (batch_id, row_sequence),
  CONSTRAINT wireless_bandwidth_windows_range_ck CHECK (window_end >= window_start)
);

CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_sensor_idx ON octopus_core.wireless_bandwidth_windows (sensor_id, window_start);
CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_threshold_idx ON octopus_core.wireless_bandwidth_windows (threshold_exceeded, window_start);
CREATE INDEX IF NOT EXISTS wireless_bandwidth_windows_source_idx ON octopus_core.wireless_bandwidth_windows (source_mac, window_start);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_alerts (
  alert_pk        bigserial,
  alert_type      VARCHAR(64) NOT NULL,
  batch_id        VARCHAR(128) DEFAULT NULL,
  row_sequence    INT DEFAULT NULL,
  alert_date      DATE DEFAULT NULL,
  detected_at     timestamptz NOT NULL,
  sensor_id       VARCHAR(64) NOT NULL,
  location_id     VARCHAR(128) NOT NULL,
  interface       VARCHAR(32) DEFAULT NULL,
  channel         SMALLINT DEFAULT NULL,
  primary_mac     VARCHAR(17) DEFAULT NULL,
  secondary_mac   VARCHAR(17) DEFAULT NULL,
  ssid            VARCHAR(256) DEFAULT NULL,
  signal_dbm      SMALLINT DEFAULT NULL,
  bytes           BIGINT DEFAULT NULL,
  details_json    jsonb DEFAULT NULL,
  raw_json        jsonb DEFAULT NULL,
  acknowledged    boolean NOT NULL DEFAULT false,
  acknowledged_by VARCHAR(128) DEFAULT NULL,
  acknowledged_at timestamptz DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (alert_pk),
  CONSTRAINT wireless_alerts_batch_uq UNIQUE (alert_type, batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS wireless_alerts_type_idx ON octopus_core.wireless_alerts (alert_type, detected_at);
CREATE INDEX IF NOT EXISTS wireless_alerts_sensor_idx ON octopus_core.wireless_alerts (sensor_id, detected_at);
CREATE INDEX IF NOT EXISTS wireless_alerts_unack_idx ON octopus_core.wireless_alerts (acknowledged, detected_at);
CREATE INDEX IF NOT EXISTS wireless_alerts_day_idx ON octopus_core.wireless_alerts (alert_type, sensor_id, primary_mac, secondary_mac, alert_date);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_alerts_ledger (
  ledger_id      bigserial,
  alert_pk       BIGINT NOT NULL,
  alert_type     VARCHAR(64) NOT NULL,
  batch_id       VARCHAR(128) DEFAULT NULL,
  row_sequence   INT DEFAULT NULL,
  alert_date     DATE DEFAULT NULL,
  detected_at    timestamptz NOT NULL,
  sensor_id      VARCHAR(64) NOT NULL,
  location_id    VARCHAR(128) NOT NULL,
  interface      VARCHAR(32) DEFAULT NULL,
  channel        SMALLINT DEFAULT NULL,
  primary_mac    VARCHAR(17) DEFAULT NULL,
  secondary_mac  VARCHAR(17) DEFAULT NULL,
  ssid           VARCHAR(256) DEFAULT NULL,
  signal_dbm     SMALLINT DEFAULT NULL,
  bytes          BIGINT DEFAULT NULL,
  details_json   jsonb DEFAULT NULL,
  raw_json       jsonb DEFAULT NULL,
  acknowledged   boolean NOT NULL,
  ledger_action  VARCHAR(16) NOT NULL,
  captured_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ledger_id)
);

CREATE INDEX IF NOT EXISTS wireless_alerts_ledger_alert_idx ON octopus_core.wireless_alerts_ledger (alert_pk, captured_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_client_inventory (
  inventory_pk    bigserial,
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
  PRIMARY KEY (inventory_pk),
  CONSTRAINT wireless_client_inventory_snapshot_uq UNIQUE (
    sensor_id, snapshot_at, client_mac
  )
);

CREATE INDEX IF NOT EXISTS wireless_client_inventory_mac_idx ON octopus_core.wireless_client_inventory (client_mac, snapshot_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_probe_requests (
  probe_pk     bigserial,
  batch_id     VARCHAR(128) NOT NULL,
  row_sequence INT NOT NULL,
  client_mac   VARCHAR(17) NOT NULL,
  ssid         VARCHAR(256) NOT NULL,
  known_bssid  VARCHAR(17) DEFAULT NULL,
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  probe_count  INT NOT NULL DEFAULT 1,
  created_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (probe_pk),
  CONSTRAINT wireless_probe_requests_batch_uq UNIQUE (batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS wireless_probe_requests_mac_idx ON octopus_core.wireless_probe_requests (client_mac, last_seen);
CREATE INDEX IF NOT EXISTS wireless_probe_requests_ssid_idx ON octopus_core.wireless_probe_requests (ssid, last_seen);
