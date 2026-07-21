-- object: wireless_clients
-- depends_on:

CREATE TABLE IF NOT EXISTS wireless_clients (
  ssid          TEXT NOT NULL,
  client_mac    TEXT NOT NULL,
  known_bssid   TEXT,
  first_seen    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  probe_count   BIGINT NOT NULL DEFAULT 1,
  location_id   TEXT,
  last_probe_batch_id VARCHAR(64),
  PRIMARY KEY (ssid(128), client_mac(17))
);
