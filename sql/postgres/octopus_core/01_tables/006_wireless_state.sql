-- object: octopus_core_wireless_state
-- depends_on: octopus_core_wireless_sink
-- Octopus maintains these dimensions, normalized facts, and state tables.

CREATE TABLE IF NOT EXISTS octopus_core.devices (
  mac_id           VARCHAR(17) NOT NULL,
  wg_pubkey        VARCHAR(128) DEFAULT NULL,
  claim_token_hash VARCHAR(255) DEFAULT NULL,
  display_name     VARCHAR(255) DEFAULT NULL,
  username         VARCHAR(255) DEFAULT NULL,
  hostname         VARCHAR(253) DEFAULT NULL,
  os_hint          VARCHAR(128) DEFAULT NULL,
  mac_hint         VARCHAR(17) NOT NULL,
  first_seen       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  notes            TEXT DEFAULT NULL,
  entity_version   BIGINT NOT NULL DEFAULT 1,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (mac_id)
);

CREATE INDEX IF NOT EXISTS devices_wg_pubkey_idx ON octopus_core.devices (wg_pubkey);
CREATE INDEX IF NOT EXISTS devices_last_seen_idx ON octopus_core.devices (last_seen);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_authorized_networks (
  id             bigserial,
  ssid           VARCHAR(256) DEFAULT NULL,
  bssid          VARCHAR(17) DEFAULT NULL,
  location_id    VARCHAR(128) DEFAULT NULL,
  label          VARCHAR(255) DEFAULT NULL,
  enabled        boolean NOT NULL DEFAULT true,
  notes          TEXT DEFAULT NULL,
  psk_ciphertext TEXT DEFAULT NULL,
  entity_version BIGINT NOT NULL DEFAULT 1,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT wireless_authorized_networks_identity_ck CHECK (
    ssid IS NOT NULL OR bssid IS NOT NULL
  )
);

CREATE INDEX IF NOT EXISTS wireless_authorized_networks_enabled_idx ON octopus_core.wireless_authorized_networks (enabled, location_id);
CREATE INDEX IF NOT EXISTS wireless_authorized_networks_bssid_idx ON octopus_core.wireless_authorized_networks (bssid);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_clients (
  ssid                VARCHAR(256) NOT NULL,
  client_mac          VARCHAR(17) NOT NULL,
  known_bssid         VARCHAR(17) DEFAULT NULL,
  first_seen          timestamptz NOT NULL,
  last_seen           timestamptz NOT NULL,
  probe_count         BIGINT NOT NULL DEFAULT 1,
  location_id         VARCHAR(128) DEFAULT NULL,
  last_probe_batch_id VARCHAR(128) DEFAULT NULL,
  updated_at          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ssid, client_mac)
);

CREATE INDEX IF NOT EXISTS wireless_clients_mac_idx ON octopus_core.wireless_clients (client_mac, last_seen);
CREATE INDEX IF NOT EXISTS wireless_clients_bssid_idx ON octopus_core.wireless_clients (known_bssid, last_seen);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_shadow_alerts (
  source_mac        VARCHAR(17) NOT NULL,
  first_occurred_at timestamptz NOT NULL,
  last_occurred_at  timestamptz NOT NULL,
  occurrence_count  BIGINT NOT NULL DEFAULT 1,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  sensor_id         VARCHAR(64) DEFAULT NULL,
  location_id       VARCHAR(128) DEFAULT NULL,
  signal_dbm        INT DEFAULT NULL,
  reason            VARCHAR(255) NOT NULL,
  evidence          jsonb NOT NULL,
  resolved_at       timestamptz DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (source_mac)
);

CREATE INDEX IF NOT EXISTS wireless_shadow_alerts_open_idx ON octopus_core.wireless_shadow_alerts (resolved_at, last_occurred_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frames (
  dedupe_key       VARCHAR(255) NOT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  schema_version   INT NOT NULL DEFAULT 1,
  observed_at      timestamptz NOT NULL,
  frame_type       VARCHAR(32) DEFAULT NULL,
  frame_subtype    VARCHAR(64) DEFAULT NULL,
  source_mac       VARCHAR(17) DEFAULT NULL,
  transmitter_mac  VARCHAR(17) DEFAULT NULL,
  receiver_mac     VARCHAR(17) DEFAULT NULL,
  bssid            VARCHAR(17) DEFAULT NULL,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  bssid_oui        VARCHAR(6) DEFAULT NULL,
  ssid             VARCHAR(256) DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_frames_sensor_idx ON octopus_core.wireless_frames (sensor_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_frames_location_idx ON octopus_core.wireless_frames (location_id, observed_at);
CREATE INDEX IF NOT EXISTS wireless_frames_source_idx ON octopus_core.wireless_frames (source_mac, observed_at);
CREATE INDEX IF NOT EXISTS wireless_frames_bssid_idx ON octopus_core.wireless_frames (bssid, observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_radio (
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
);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_qos (
  dedupe_key          VARCHAR(255) NOT NULL,
  qos_tid             INT DEFAULT NULL,
  qos_eosp            boolean DEFAULT NULL,
  qos_ack_policy      INT DEFAULT NULL,
  qos_ack_policy_label VARCHAR(64) DEFAULT NULL,
  qos_amsdu           boolean DEFAULT NULL,
  more_data           boolean NOT NULL DEFAULT false,
  retry               boolean NOT NULL DEFAULT false,
  power_save          boolean NOT NULL DEFAULT false,
  protected           boolean NOT NULL DEFAULT false,
  frame_control_flags INT NOT NULL DEFAULT 0,
  PRIMARY KEY (dedupe_key)
);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_network (
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
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_frame_network_src_idx ON octopus_core.wireless_frame_network (src_ip);
CREATE INDEX IF NOT EXISTS wireless_frame_network_dst_idx ON octopus_core.wireless_frame_network (dst_ip);
CREATE INDEX IF NOT EXISTS wireless_frame_network_app_idx ON octopus_core.wireless_frame_network (app_protocol);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_app_signals (
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
);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_identity (
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
  handshake_captured boolean NOT NULL DEFAULT false,
  normalized_text    TEXT DEFAULT NULL,
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_frame_identity_session_idx ON octopus_core.wireless_frame_identity (session_key);
CREATE INDEX IF NOT EXISTS wireless_frame_identity_fingerprint_idx ON octopus_core.wireless_frame_identity (device_fingerprint);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_frame_security (
  dedupe_key              VARCHAR(255) NOT NULL,
  large_frame             boolean NOT NULL DEFAULT false,
  mixed_encryption        boolean DEFAULT NULL,
  dedupe_or_replay_suspect boolean NOT NULL DEFAULT false,
  raw_len                 INT NOT NULL DEFAULT 0,
  security_flags          INT NOT NULL DEFAULT 0,
  risk_score              double precision DEFAULT NULL,
  tags                     jsonb NOT NULL,
  signal_status            VARCHAR(64) DEFAULT NULL,
  adjacent_mac_hint        VARCHAR(17) DEFAULT NULL,
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_frame_security_risk_idx ON octopus_core.wireless_frame_security (risk_score);
