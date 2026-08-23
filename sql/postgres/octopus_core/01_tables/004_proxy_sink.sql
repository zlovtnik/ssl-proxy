-- object: octopus_core_proxy_sink
-- depends_on: octopus_core_ingestion_evidence
-- High-volume facts deliberately have no foreign keys.

CREATE TABLE IF NOT EXISTS octopus_core.proxy_events (
  id                  bigserial,
  batch_id            uuid NOT NULL,
  row_sequence        INT NOT NULL,
  event_time          timestamptz NOT NULL,
  event_timestamp_utc timestamptz NOT NULL,
  event_type          VARCHAR(32) NOT NULL,
  host                VARCHAR(253) NOT NULL,
  peer_ip             VARCHAR(45) DEFAULT NULL,
  wg_pubkey           VARCHAR(128) DEFAULT NULL,
  device_id           uuid DEFAULT NULL,
  identity_source     VARCHAR(64) NOT NULL DEFAULT 'unknown',
  peer_hostname       VARCHAR(253) DEFAULT NULL,
  client_ua           VARCHAR(512) DEFAULT NULL,
  bytes_up            BIGINT NOT NULL DEFAULT 0,
  bytes_down          BIGINT NOT NULL DEFAULT 0,
  status_code         INT DEFAULT NULL,
  blocked             boolean NOT NULL DEFAULT false,
  obfuscation_profile VARCHAR(32) DEFAULT NULL,
  correlation_id      uuid DEFAULT NULL,
  parent_event_id     BIGINT DEFAULT NULL,
  event_sequence      INT DEFAULT NULL,
  duration_ms         BIGINT DEFAULT NULL,
  reason              VARCHAR(64) DEFAULT NULL,
  raw_json            jsonb DEFAULT NULL,
  created_at          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT proxy_events_batch_row_uq UNIQUE (batch_id, row_sequence)
);

CREATE INDEX IF NOT EXISTS proxy_events_event_utc_idx ON octopus_core.proxy_events (event_timestamp_utc);
CREATE INDEX IF NOT EXISTS proxy_events_host_time_idx ON octopus_core.proxy_events (host, event_time);
CREATE INDEX IF NOT EXISTS proxy_events_blocked_time_idx ON octopus_core.proxy_events (blocked, event_time, host);
CREATE INDEX IF NOT EXISTS proxy_events_device_time_idx ON octopus_core.proxy_events (device_id, event_time);
CREATE INDEX IF NOT EXISTS proxy_events_wg_time_idx ON octopus_core.proxy_events (wg_pubkey, event_time);

CREATE TABLE IF NOT EXISTS octopus_core.proxy_blocked_host_rollups (
  id                 bigserial,
  host               VARCHAR(253) NOT NULL,
  blocked_attempts   BIGINT NOT NULL DEFAULT 0,
  blocked_bytes      BIGINT NOT NULL DEFAULT 0,
  frequency_hz       DECIMAL(18,6) NOT NULL DEFAULT 0,
  verdict            VARCHAR(32) NOT NULL,
  category           VARCHAR(64) DEFAULT NULL,
  risk_score         DECIMAL(10,4) NOT NULL DEFAULT 0,
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
  PRIMARY KEY (id),
  CONSTRAINT proxy_blocked_host_rollups_host_uq UNIQUE (host)
);

CREATE INDEX IF NOT EXISTS proxy_blocked_host_rollups_updated_idx ON octopus_core.proxy_blocked_host_rollups (updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.proxy_payload_audit (
  id                 bigserial,
  correlation_id     uuid NOT NULL,
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
  PRIMARY KEY (id),
  CONSTRAINT proxy_payload_audit_capture_uq UNIQUE (
    correlation_id, host, direction, captured_at, byte_offset
  ),
  CONSTRAINT proxy_payload_audit_direction_ck CHECK (direction IN ('UP', 'DOWN'))
);

CREATE INDEX IF NOT EXISTS proxy_payload_audit_host_idx ON octopus_core.proxy_payload_audit (host, captured_at);
