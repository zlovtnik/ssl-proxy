-- object: octopus_core_ingestion_evidence
-- depends_on: octopus_core_sync_state

CREATE TABLE IF NOT EXISTS octopus_core.ingestion_evidence (
  topic             VARCHAR(255) NOT NULL,
  partition_id      INT NOT NULL,
  record_offset     BIGINT NOT NULL,
  group_id          VARCHAR(128) NOT NULL,
  group_version     VARCHAR(64) NOT NULL,
  artifact_sha256   char(64) NOT NULL,
  message_key       VARCHAR(512) DEFAULT NULL,
  payload_sha256    char(64) NOT NULL,
  disposition       VARCHAR(32) NOT NULL DEFAULT 'received',
  dedupe_key        VARCHAR(255) DEFAULT NULL,
  first_seen_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, topic, partition_id, record_offset),
  CONSTRAINT ingestion_evidence_disposition_ck CHECK (
    disposition IN ('received', 'duplicate', 'accepted', 'processed', 'rejected', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS ingestion_evidence_dedupe_idx ON octopus_core.ingestion_evidence (dedupe_key);
CREATE INDEX IF NOT EXISTS ingestion_evidence_disposition_idx ON octopus_core.ingestion_evidence (disposition, updated_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_events (
  dedupe_key     VARCHAR(255) NOT NULL,
  stream_name    VARCHAR(255) NOT NULL,
  observed_at    timestamptz NOT NULL,
  payload_ref    TEXT NOT NULL,
  payload        jsonb DEFAULT NULL,
  payload_sha256 char(64) DEFAULT NULL,
  status         VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count  INT NOT NULL DEFAULT 0,
  last_error     TEXT DEFAULT NULL,
  producer       VARCHAR(128) NOT NULL DEFAULT 'unknown',
  event_kind     VARCHAR(64) DEFAULT NULL,
  payload_archive_uri VARCHAR(2048) DEFAULT NULL,
  archived_payload_bytes BIGINT DEFAULT NULL,
  payload_archived_at timestamptz DEFAULT NULL,
  payload_archived boolean NOT NULL DEFAULT false,
  sensor_id      VARCHAR(64) DEFAULT NULL,
  location_id    VARCHAR(128) DEFAULT NULL,
  username       VARCHAR(255) DEFAULT NULL,
  event_type     VARCHAR(64) DEFAULT NULL,
  schema_version INT DEFAULT NULL,
  frame_type     VARCHAR(32) DEFAULT NULL,
  frame_subtype  VARCHAR(64) DEFAULT NULL,
  source_mac     VARCHAR(17) DEFAULT NULL,
  transmitter_mac VARCHAR(17) DEFAULT NULL,
  receiver_mac   VARCHAR(17) DEFAULT NULL,
  bssid          VARCHAR(17) DEFAULT NULL,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  ssid           VARCHAR(256) DEFAULT NULL,
  signal_dbm     INT DEFAULT NULL,
  noise_dbm      INT DEFAULT NULL,
  frequency_mhz  INT DEFAULT NULL,
  channel_flags  INT DEFAULT NULL,
  data_rate_kbps INT DEFAULT NULL,
  antenna_id     INT DEFAULT NULL,
  tsft           BIGINT DEFAULT NULL,
  fragment_number INT DEFAULT NULL,
  channel_number INT DEFAULT NULL,
  signal_status  VARCHAR(64) DEFAULT NULL,
  adjacent_mac_hint VARCHAR(17) DEFAULT NULL,
  qos_tid        INT DEFAULT NULL,
  qos_eosp       boolean DEFAULT NULL,
  qos_ack_policy INT DEFAULT NULL,
  qos_ack_policy_label VARCHAR(64) DEFAULT NULL,
  qos_amsdu      boolean DEFAULT NULL,
  llc_oui        VARCHAR(16) DEFAULT NULL,
  ethertype      INT DEFAULT NULL,
  ethertype_name VARCHAR(64) DEFAULT NULL,
  src_ip         VARCHAR(45) DEFAULT NULL,
  dst_ip         VARCHAR(45) DEFAULT NULL,
  ip_ttl         INT DEFAULT NULL,
  ip_protocol    INT DEFAULT NULL,
  ip_protocol_name VARCHAR(64) DEFAULT NULL,
  src_port       INT DEFAULT NULL,
  dst_port       INT DEFAULT NULL,
  transport_protocol VARCHAR(32) DEFAULT NULL,
  transport_length INT DEFAULT NULL,
  transport_checksum INT DEFAULT NULL,
  app_protocol   VARCHAR(64) DEFAULT NULL,
  ssdp_message_type VARCHAR(64) DEFAULT NULL,
  ssdp_st        VARCHAR(512) DEFAULT NULL,
  ssdp_mx        VARCHAR(64) DEFAULT NULL,
  ssdp_usn       VARCHAR(512) DEFAULT NULL,
  dhcp_requested_ip VARCHAR(45) DEFAULT NULL,
  dhcp_hostname  VARCHAR(253) DEFAULT NULL,
  dhcp_vendor_class VARCHAR(255) DEFAULT NULL,
  dns_query_name VARCHAR(253) DEFAULT NULL,
  mdns_name      VARCHAR(253) DEFAULT NULL,
  session_key    VARCHAR(255) DEFAULT NULL,
  retransmit_key VARCHAR(255) DEFAULT NULL,
  frame_fingerprint VARCHAR(255) DEFAULT NULL,
  payload_visibility VARCHAR(64) DEFAULT NULL,
  tsft_delta_us  BIGINT DEFAULT NULL,
  wall_clock_delta_ms BIGINT DEFAULT NULL,
  large_frame    boolean NOT NULL DEFAULT false,
  mixed_encryption boolean DEFAULT NULL,
  dedupe_or_replay_suspect boolean NOT NULL DEFAULT false,
  raw_len        INT NOT NULL DEFAULT 0,
  frame_control_flags INT NOT NULL DEFAULT 0,
  more_data      boolean NOT NULL DEFAULT false,
  retry          boolean NOT NULL DEFAULT false,
  power_save     boolean NOT NULL DEFAULT false,
  protected      boolean NOT NULL DEFAULT false,
  security_flags INT NOT NULL DEFAULT 0,
  risk_score     double precision DEFAULT NULL,
  identity_source VARCHAR(64) DEFAULT NULL,
  tags           jsonb DEFAULT NULL,
  wps_device_name VARCHAR(255) DEFAULT NULL,
  wps_manufacturer VARCHAR(255) DEFAULT NULL,
  wps_model_name VARCHAR(255) DEFAULT NULL,
  device_fingerprint VARCHAR(255) DEFAULT NULL,
  handshake_captured boolean NOT NULL DEFAULT false,
  wireless_search_text TEXT DEFAULT NULL,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name),
  CONSTRAINT sync_events_status_ck CHECK (
    status IN ('pending', 'processing', 'batched', 'completed', 'failed')
  )
);

CREATE INDEX IF NOT EXISTS sync_events_status_idx ON octopus_core.sync_events (status, updated_at);
CREATE INDEX IF NOT EXISTS sync_events_stream_status_idx ON octopus_core.sync_events (stream_name, status, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_observed_idx ON octopus_core.sync_events (observed_at);
CREATE INDEX IF NOT EXISTS sync_events_sensor_observed_idx ON octopus_core.sync_events (sensor_id, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_source_observed_idx ON octopus_core.sync_events (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_bssid_observed_idx ON octopus_core.sync_events (bssid, observed_at);
CREATE INDEX IF NOT EXISTS sync_events_location_observed_idx ON octopus_core.sync_events (location_id, observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_event_payload_archives (
  dedupe_key     VARCHAR(255) NOT NULL,
  stream_name    VARCHAR(255) NOT NULL,
  observed_at    timestamptz NOT NULL,
  payload_sha256 char(64) DEFAULT NULL,
  archive_uri    VARCHAR(2048) NOT NULL,
  payload_bytes  BIGINT NOT NULL DEFAULT 0,
  archived_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name)
);

CREATE INDEX IF NOT EXISTS sync_event_archives_age_idx ON octopus_core.sync_event_payload_archives (archived_at);

CREATE TABLE IF NOT EXISTS octopus_core.sync_event_tombstones (
  dedupe_key     VARCHAR(255) NOT NULL,
  stream_name    VARCHAR(255) NOT NULL,
  payload_sha256 char(64) DEFAULT NULL,
  observed_at    timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key, stream_name)
);

CREATE INDEX IF NOT EXISTS sync_event_tombstones_expiry_idx ON octopus_core.sync_event_tombstones (expires_at);
