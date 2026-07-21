-- object: octopus_core_wireless_state
-- depends_on: octopus_core_wireless_sink
-- Octopus maintains these dimensions, normalized facts, and state tables.

USE octopus_core;

CREATE TABLE IF NOT EXISTS devices (
  mac_id           VARCHAR(17) NOT NULL,
  wg_pubkey        VARCHAR(128) DEFAULT NULL,
  claim_token_hash VARCHAR(255) DEFAULT NULL,
  display_name     VARCHAR(255) DEFAULT NULL,
  username         VARCHAR(255) DEFAULT NULL,
  hostname         VARCHAR(253) DEFAULT NULL,
  os_hint          VARCHAR(128) DEFAULT NULL,
  mac_hint         VARCHAR(17) NOT NULL,
  first_seen       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  notes            TEXT DEFAULT NULL,
  entity_version   BIGINT NOT NULL DEFAULT 1,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (mac_id),
  KEY devices_wg_pubkey_idx (wg_pubkey),
  KEY devices_last_seen_idx (last_seen)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_authorized_networks (
  id             BIGINT NOT NULL AUTO_INCREMENT,
  ssid           VARCHAR(256) DEFAULT NULL,
  bssid          VARCHAR(17) DEFAULT NULL,
  location_id    VARCHAR(128) DEFAULT NULL,
  label          VARCHAR(255) DEFAULT NULL,
  enabled        TINYINT(1) NOT NULL DEFAULT 1,
  notes          TEXT DEFAULT NULL,
  psk_ciphertext TEXT DEFAULT NULL,
  entity_version BIGINT NOT NULL DEFAULT 1,
  created_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY wireless_authorized_networks_enabled_idx (enabled, location_id),
  KEY wireless_authorized_networks_bssid_idx (bssid),
  CONSTRAINT wireless_authorized_networks_identity_ck CHECK (
    ssid IS NOT NULL OR bssid IS NOT NULL
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_clients (
  ssid                VARCHAR(256) NOT NULL,
  client_mac          VARCHAR(17) NOT NULL,
  known_bssid         VARCHAR(17) DEFAULT NULL,
  first_seen          DATETIME(6) NOT NULL,
  last_seen           DATETIME(6) NOT NULL,
  probe_count         BIGINT NOT NULL DEFAULT 1,
  location_id         VARCHAR(128) DEFAULT NULL,
  last_probe_batch_id VARCHAR(128) DEFAULT NULL,
  updated_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (ssid, client_mac),
  KEY wireless_clients_mac_idx (client_mac, last_seen),
  KEY wireless_clients_bssid_idx (known_bssid, last_seen)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_shadow_alerts (
  source_mac        VARCHAR(17) NOT NULL,
  first_occurred_at DATETIME(6) NOT NULL,
  last_occurred_at  DATETIME(6) NOT NULL,
  occurrence_count  BIGINT NOT NULL DEFAULT 1,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  sensor_id         VARCHAR(64) DEFAULT NULL,
  location_id       VARCHAR(128) DEFAULT NULL,
  signal_dbm        INT DEFAULT NULL,
  reason            VARCHAR(255) NOT NULL,
  evidence          JSON NOT NULL,
  resolved_at       DATETIME(6) DEFAULT NULL,
  created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (source_mac),
  KEY wireless_shadow_alerts_open_idx (resolved_at, last_occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frames (
  dedupe_key       VARCHAR(255) NOT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  schema_version   INT NOT NULL DEFAULT 1,
  observed_at      DATETIME(6) NOT NULL,
  frame_type       VARCHAR(32) DEFAULT NULL,
  frame_subtype    VARCHAR(64) DEFAULT NULL,
  source_mac       VARCHAR(17) DEFAULT NULL,
  transmitter_mac  VARCHAR(17) DEFAULT NULL,
  receiver_mac     VARCHAR(17) DEFAULT NULL,
  bssid            VARCHAR(17) DEFAULT NULL,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  bssid_oui        VARCHAR(6) DEFAULT NULL,
  ssid             VARCHAR(256) DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key),
  KEY wireless_frames_sensor_idx (sensor_id, observed_at),
  KEY wireless_frames_location_idx (location_id, observed_at),
  KEY wireless_frames_source_idx (source_mac, observed_at),
  KEY wireless_frames_bssid_idx (bssid, observed_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_radio (
  dedupe_key         VARCHAR(255) NOT NULL,
  signal_dbm         INT DEFAULT NULL,
  noise_dbm          INT DEFAULT NULL,
  frequency_mhz      INT DEFAULT NULL,
  channel_flags      INT DEFAULT NULL,
  data_rate_kbps     INT DEFAULT NULL,
  antenna_id         INT DEFAULT NULL,
  tsft               BIGINT DEFAULT NULL,
  fragment_number    INT DEFAULT NULL,
  channel_number     INT DEFAULT NULL,
  tsft_delta_us      BIGINT DEFAULT NULL,
  wall_clock_delta_ms BIGINT DEFAULT NULL,
  PRIMARY KEY (dedupe_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_qos (
  dedupe_key          VARCHAR(255) NOT NULL,
  qos_tid             INT DEFAULT NULL,
  qos_eosp            TINYINT(1) DEFAULT NULL,
  qos_ack_policy      INT DEFAULT NULL,
  qos_ack_policy_label VARCHAR(64) DEFAULT NULL,
  qos_amsdu           TINYINT(1) DEFAULT NULL,
  more_data           TINYINT(1) NOT NULL DEFAULT 0,
  retry               TINYINT(1) NOT NULL DEFAULT 0,
  power_save          TINYINT(1) NOT NULL DEFAULT 0,
  protected           TINYINT(1) NOT NULL DEFAULT 0,
  frame_control_flags INT NOT NULL DEFAULT 0,
  PRIMARY KEY (dedupe_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_network (
  dedupe_key        VARCHAR(255) NOT NULL,
  llc_oui           VARCHAR(16) DEFAULT NULL,
  ethertype         INT DEFAULT NULL,
  ethertype_name    VARCHAR(64) DEFAULT NULL,
  src_ip            VARCHAR(45) DEFAULT NULL,
  dst_ip            VARCHAR(45) DEFAULT NULL,
  ip_ttl            INT DEFAULT NULL,
  ip_protocol       INT DEFAULT NULL,
  ip_protocol_name  VARCHAR(64) DEFAULT NULL,
  src_port          INT DEFAULT NULL,
  dst_port          INT DEFAULT NULL,
  transport_protocol VARCHAR(32) DEFAULT NULL,
  transport_length  INT DEFAULT NULL,
  transport_checksum INT DEFAULT NULL,
  app_protocol      VARCHAR(64) DEFAULT NULL,
  PRIMARY KEY (dedupe_key),
  KEY wireless_frame_network_src_idx (src_ip),
  KEY wireless_frame_network_dst_idx (dst_ip),
  KEY wireless_frame_network_app_idx (app_protocol)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_app_signals (
  dedupe_key        VARCHAR(255) NOT NULL,
  ssdp_message_type VARCHAR(64) DEFAULT NULL,
  ssdp_st           VARCHAR(512) DEFAULT NULL,
  ssdp_mx           VARCHAR(64) DEFAULT NULL,
  ssdp_usn          VARCHAR(512) DEFAULT NULL,
  dhcp_requested_ip VARCHAR(45) DEFAULT NULL,
  dhcp_hostname     VARCHAR(253) DEFAULT NULL,
  dhcp_vendor_class VARCHAR(255) DEFAULT NULL,
  dns_query_name    VARCHAR(253) DEFAULT NULL,
  mdns_name         VARCHAR(253) DEFAULT NULL,
  PRIMARY KEY (dedupe_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_identity (
  dedupe_key         VARCHAR(255) NOT NULL,
  username           VARCHAR(255) DEFAULT NULL,
  event_type         VARCHAR(64) DEFAULT NULL,
  session_key        VARCHAR(255) DEFAULT NULL,
  retransmit_key     VARCHAR(255) DEFAULT NULL,
  frame_fingerprint  VARCHAR(255) DEFAULT NULL,
  payload_visibility VARCHAR(64) DEFAULT NULL,
  identity_source    VARCHAR(64) DEFAULT NULL,
  device_fingerprint VARCHAR(255) DEFAULT NULL,
  wps_device_name    VARCHAR(255) DEFAULT NULL,
  wps_manufacturer   VARCHAR(255) DEFAULT NULL,
  wps_model_name     VARCHAR(255) DEFAULT NULL,
  handshake_captured TINYINT(1) NOT NULL DEFAULT 0,
  normalized_text    TEXT DEFAULT NULL,
  PRIMARY KEY (dedupe_key),
  KEY wireless_frame_identity_session_idx (session_key),
  KEY wireless_frame_identity_fingerprint_idx (device_fingerprint)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_frame_security (
  dedupe_key              VARCHAR(255) NOT NULL,
  large_frame             TINYINT(1) NOT NULL DEFAULT 0,
  mixed_encryption        TINYINT(1) DEFAULT NULL,
  dedupe_or_replay_suspect TINYINT(1) NOT NULL DEFAULT 0,
  raw_len                 INT NOT NULL DEFAULT 0,
  security_flags          INT NOT NULL DEFAULT 0,
  risk_score              DOUBLE DEFAULT NULL,
  tags                     JSON NOT NULL,
  signal_status            VARCHAR(64) DEFAULT NULL,
  adjacent_mac_hint        VARCHAR(17) DEFAULT NULL,
  PRIMARY KEY (dedupe_key),
  KEY wireless_frame_security_risk_idx (risk_score)
) ENGINE=InnoDB;
