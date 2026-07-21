-- object: wireless_shadow_alerts
-- depends_on:

CREATE TABLE IF NOT EXISTS wireless_shadow_alerts (
  source_mac        VARCHAR(17) NOT NULL,
  first_occurred_at DATETIME(6),
  last_occurred_at  DATETIME(6),
  occurrence_count  INT NOT NULL DEFAULT 1,
  destination_bssid TEXT,
  ssid              TEXT,
  sensor_id         TEXT,
  location_id       TEXT,
  signal_dbm        INT,
  reason            TEXT,
  evidence          JSON,
  resolved_at       DATETIME(6),
  created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (source_mac)
);
