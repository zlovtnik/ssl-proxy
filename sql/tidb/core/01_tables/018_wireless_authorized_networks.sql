-- object: wireless_authorized_networks
-- depends_on:

CREATE TABLE IF NOT EXISTS wireless_authorized_networks (
  id            BIGINT AUTO_INCREMENT NOT NULL,
  ssid          TEXT,
  bssid         TEXT,
  location_id   TEXT,
  label         TEXT,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  notes         TEXT,
  psk_ciphertext TEXT,
  created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  INDEX idx_wan_enabled (enabled)
);
