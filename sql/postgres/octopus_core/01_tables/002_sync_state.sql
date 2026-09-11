-- object: octopus_core_configuration_and_checkpoints
-- depends_on: octopus_core_schema_control

CREATE TABLE IF NOT EXISTS octopus_core.registered_devices (
  device_id         uuid NOT NULL,
  mac                VARCHAR(17) NOT NULL,
  wireguard_pubkey   VARCHAR(128) DEFAULT NULL,
  claim_token_hash   VARCHAR(255) DEFAULT NULL,
  display_name       VARCHAR(255) DEFAULT NULL,
  username           VARCHAR(255) DEFAULT NULL,
  hostname           VARCHAR(253) DEFAULT NULL,
  labels             jsonb NOT NULL DEFAULT '{}'::jsonb,
  public_keys        jsonb NOT NULL DEFAULT '[]'::jsonb,
  notes              TEXT DEFAULT NULL,
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (device_id),
  CONSTRAINT registered_devices_mac_uq UNIQUE (mac),
  CONSTRAINT registered_devices_mac_ck CHECK (mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'),
  CONSTRAINT registered_devices_labels_ck CHECK (jsonb_typeof(labels) = 'object'),
  CONSTRAINT registered_devices_keys_ck CHECK (jsonb_typeof(public_keys) = 'array')
);

CREATE INDEX IF NOT EXISTS registered_devices_wireguard_idx
  ON octopus_core.registered_devices (wireguard_pubkey);

CREATE TABLE IF NOT EXISTS octopus_core.authorized_networks (
  network_id             uuid NOT NULL,
  ssid                   VARCHAR(256) DEFAULT NULL,
  bssid                  VARCHAR(17) DEFAULT NULL,
  location_id            VARCHAR(128) DEFAULT NULL,
  label                  VARCHAR(255) DEFAULT NULL,
  enabled                boolean NOT NULL DEFAULT true,
  credential_ciphertext  bytea DEFAULT NULL,
  credential_nonce       bytea DEFAULT NULL,
  credential_key_version INT DEFAULT NULL,
  notes                  TEXT DEFAULT NULL,
  created_at             timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at             timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (network_id),
  CONSTRAINT authorized_networks_identity_ck CHECK (ssid IS NOT NULL OR bssid IS NOT NULL),
  CONSTRAINT authorized_networks_bssid_ck CHECK (
    bssid IS NULL OR bssid ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
  ),
  CONSTRAINT authorized_networks_credential_ck CHECK (
    (credential_ciphertext IS NULL AND credential_nonce IS NULL AND credential_key_version IS NULL)
    OR
    (credential_ciphertext IS NOT NULL AND credential_nonce IS NOT NULL AND credential_key_version IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS authorized_networks_enabled_idx
  ON octopus_core.authorized_networks (enabled, location_id);

CREATE TABLE IF NOT EXISTS octopus_core.consumer_checkpoints (
  consumer_group   VARCHAR(128) NOT NULL,
  topic            VARCHAR(255) NOT NULL,
  partition_id     INT NOT NULL,
  next_offset      BIGINT NOT NULL,
  group_version    VARCHAR(64) NOT NULL,
  artifact_sha256  char(64) NOT NULL,
  cursor_value     TEXT DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (consumer_group, topic, partition_id),
  CONSTRAINT consumer_checkpoints_partition_ck CHECK (partition_id >= 0),
  CONSTRAINT consumer_checkpoints_offset_ck CHECK (next_offset >= 0)
);
