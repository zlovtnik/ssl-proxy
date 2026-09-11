-- object: octopus_core_wireless_observations_alerts_sensors
-- depends_on: octopus_core_ingestion_work_and_failures

CREATE TABLE IF NOT EXISTS octopus_core.wireless_observations (
  event_id              VARCHAR(255) NOT NULL,
  schema_version        INT NOT NULL,
  observation_subtype   VARCHAR(64) NOT NULL,
  observed_at           timestamptz NOT NULL,
  produced_at           timestamptz NOT NULL,
  sensor_id             VARCHAR(64) NOT NULL,
  location_id           VARCHAR(128) DEFAULT NULL,
  correlation_id        VARCHAR(255) DEFAULT NULL,
  causation_id          VARCHAR(255) DEFAULT NULL,
  source_mac            VARCHAR(17) DEFAULT NULL,
  transmitter_mac       VARCHAR(17) DEFAULT NULL,
  receiver_mac          VARCHAR(17) DEFAULT NULL,
  bssid                 VARCHAR(17) DEFAULT NULL,
  destination_bssid     VARCHAR(17) DEFAULT NULL,
  ssid                  VARCHAR(256) DEFAULT NULL,
  signal_dbm            INT DEFAULT NULL,
  frequency_mhz         INT DEFAULT NULL,
  channel_number        INT DEFAULT NULL,
  security_flags        INT NOT NULL DEFAULT 0,
  handshake_captured    boolean NOT NULL DEFAULT false,
  payload               jsonb NOT NULL,
  payload_sha256        char(64) NOT NULL,
  receipt_consumer_group VARCHAR(128) NOT NULL,
  receipt_topic         VARCHAR(255) NOT NULL,
  receipt_partition_id  INT NOT NULL,
  receipt_record_offset BIGINT NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id),
  CONSTRAINT wireless_observations_schema_version_ck CHECK (schema_version > 0),
  CONSTRAINT wireless_observations_payload_ck CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT wireless_observations_receipt_uq UNIQUE (
    receipt_consumer_group, receipt_topic, receipt_partition_id, receipt_record_offset
  )
);

CREATE INDEX IF NOT EXISTS wireless_observations_sensor_idx
  ON octopus_core.wireless_observations (sensor_id, observed_at DESC, event_id);
CREATE INDEX IF NOT EXISTS wireless_observations_source_idx
  ON octopus_core.wireless_observations (source_mac, observed_at DESC, event_id);
CREATE INDEX IF NOT EXISTS wireless_observations_bssid_idx
  ON octopus_core.wireless_observations (bssid, observed_at DESC, event_id);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_alerts (
  alert_id        uuid NOT NULL,
  alert_type      VARCHAR(64) NOT NULL,
  subject_kind    VARCHAR(32) NOT NULL,
  subject_id      VARCHAR(255) NOT NULL,
  severity        VARCHAR(16) NOT NULL,
  evidence        jsonb NOT NULL,
  source_event_id VARCHAR(255) NOT NULL,
  detected_at     timestamptz NOT NULL,
  resolved_at     timestamptz DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (alert_id),
  CONSTRAINT wireless_alerts_source_type_uq UNIQUE (source_event_id, alert_type),
  CONSTRAINT wireless_alerts_subject_kind_ck CHECK (
    subject_kind IN ('access_point', 'station', 'sensor', 'network', 'unknown')
  ),
  CONSTRAINT wireless_alerts_severity_ck CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  CONSTRAINT wireless_alerts_evidence_ck CHECK (jsonb_typeof(evidence) = 'object')
);

CREATE INDEX IF NOT EXISTS wireless_alerts_open_idx
  ON octopus_core.wireless_alerts (resolved_at, severity, detected_at DESC);
CREATE INDEX IF NOT EXISTS wireless_alerts_subject_idx
  ON octopus_core.wireless_alerts (subject_kind, subject_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS octopus_core.sensors (
  sensor_id       VARCHAR(64) NOT NULL,
  location_id     VARCHAR(128) DEFAULT NULL,
  capabilities    jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at   timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL,
  last_heartbeat_at timestamptz DEFAULT NULL,
  status          VARCHAR(32) NOT NULL DEFAULT 'observed',
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (sensor_id),
  CONSTRAINT sensors_seen_ck CHECK (first_seen_at <= last_seen_at),
  CONSTRAINT sensors_status_ck CHECK (status IN ('observed', 'online', 'offline', 'disabled')),
  CONSTRAINT sensors_capabilities_ck CHECK (jsonb_typeof(capabilities) = 'object'),
  CONSTRAINT sensors_metadata_ck CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON octopus_core.sensors (last_seen_at DESC, sensor_id);
