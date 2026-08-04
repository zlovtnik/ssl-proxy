-- object: octopus_core_proxy_sink
-- depends_on: octopus_core_ingestion_evidence
-- High-volume facts deliberately have no foreign keys.

USE octopus_core;

CREATE TABLE IF NOT EXISTS proxy_events (
  id                  BIGINT NOT NULL AUTO_INCREMENT,
  batch_id            CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  row_sequence        INT NOT NULL,
  event_time          DATETIME(6) NOT NULL,
  event_timestamp_utc DATETIME(6) NOT NULL,
  event_type          VARCHAR(32) NOT NULL,
  host                VARCHAR(253) NOT NULL,
  peer_ip             VARCHAR(45) DEFAULT NULL,
  wg_pubkey           VARCHAR(128) DEFAULT NULL,
  device_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  identity_source     VARCHAR(64) NOT NULL DEFAULT 'unknown',
  peer_hostname       VARCHAR(253) DEFAULT NULL,
  client_ua           VARCHAR(512) DEFAULT NULL,
  bytes_up            BIGINT NOT NULL DEFAULT 0,
  bytes_down          BIGINT NOT NULL DEFAULT 0,
  status_code         INT DEFAULT NULL,
  blocked             TINYINT(1) NOT NULL DEFAULT 0,
  obfuscation_profile VARCHAR(32) DEFAULT NULL,
  correlation_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  parent_event_id     BIGINT DEFAULT NULL,
  event_sequence      INT DEFAULT NULL,
  duration_ms         BIGINT DEFAULT NULL,
  reason              VARCHAR(64) DEFAULT NULL,
  raw_json            JSON DEFAULT NULL,
  created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY proxy_events_batch_row_uq (batch_id, row_sequence),
  KEY proxy_events_event_utc_idx (event_timestamp_utc),
  KEY proxy_events_host_time_idx (host, event_time),
  KEY proxy_events_blocked_time_idx (blocked, event_time),
  KEY proxy_events_device_time_idx (device_id, event_time),
  KEY proxy_events_wg_time_idx (wg_pubkey, event_time)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS proxy_blocked_host_rollups (
  id                 BIGINT NOT NULL AUTO_INCREMENT,
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
  first_seen         DATETIME(6) NOT NULL,
  updated_at         DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY proxy_blocked_host_rollups_host_uq (host),
  KEY proxy_blocked_host_rollups_updated_idx (updated_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS proxy_payload_audit (
  id                 BIGINT NOT NULL AUTO_INCREMENT,
  correlation_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  host               VARCHAR(253) NOT NULL,
  direction          VARCHAR(4) NOT NULL,
  captured_at        DATETIME(6) NOT NULL,
  byte_offset        INT NOT NULL DEFAULT 0,
  payload_object_key VARCHAR(1024) DEFAULT NULL,
  content_type       VARCHAR(128) DEFAULT NULL,
  http_method        VARCHAR(16) DEFAULT NULL,
  http_status        INT DEFAULT NULL,
  http_path          VARCHAR(2048) DEFAULT NULL,
  is_encrypted       TINYINT(1) NOT NULL DEFAULT 0,
  truncated          TINYINT(1) NOT NULL DEFAULT 0,
  peer_ip            VARCHAR(45) DEFAULT NULL,
  notes              VARCHAR(512) DEFAULT NULL,
  created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY proxy_payload_audit_capture_uq (
    correlation_id, host, direction, captured_at, byte_offset
  ),
  KEY proxy_payload_audit_host_idx (host, captured_at),
  CONSTRAINT proxy_payload_audit_direction_ck CHECK (direction IN ('UP', 'DOWN'))
) ENGINE=InnoDB;
