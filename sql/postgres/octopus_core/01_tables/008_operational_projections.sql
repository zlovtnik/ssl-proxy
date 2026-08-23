-- object: octopus_core_operational_projections
-- depends_on: octopus_core_processor_leases_and_outbox, octopus_core_wireless_state
-- These are physical, incrementally maintained tables. Their legacy v_/mv_
-- names preserve the Rails read contract without PostgreSQL materialized views.

CREATE TABLE IF NOT EXISTS octopus_core.sensors (
  id              bigserial,
  sensor_id       VARCHAR(64) NOT NULL,
  location_id     VARCHAR(128) NOT NULL,
  interface       VARCHAR(32) DEFAULT NULL,
  channel         INT DEFAULT NULL,
  last_signal_dbm INT DEFAULT NULL,
  last_seen_at    timestamptz DEFAULT NULL,
  status          VARCHAR(32) NOT NULL DEFAULT 'unknown',
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT sensors_sensor_id_uq UNIQUE (sensor_id)
);

CREATE INDEX IF NOT EXISTS sensors_status_seen_idx ON octopus_core.sensors (status, last_seen_at);

CREATE TABLE IF NOT EXISTS octopus_core.sensor_alerts (
  id          bigserial,
  sensor_id   VARCHAR(64) NOT NULL,
  alert_type  VARCHAR(64) NOT NULL,
  severity    VARCHAR(32) NOT NULL,
  message     TEXT NOT NULL,
  payload     jsonb NOT NULL,
  resolved_at timestamptz DEFAULT NULL,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS sensor_alerts_open_idx ON octopus_core.sensor_alerts (sensor_id, alert_type, resolved_at);

CREATE TABLE IF NOT EXISTS octopus_core.redpanda_traffic_samples (
  id          bigserial,
  topic       VARCHAR(255) NOT NULL,
  sensor_id   VARCHAR(64) DEFAULT NULL,
  sampled_at  timestamptz NOT NULL,
  event_count BIGINT NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT redpanda_traffic_samples_sample_uq UNIQUE (topic, sensor_id, sampled_at)
);

CREATE INDEX IF NOT EXISTS redpanda_traffic_samples_time_idx ON octopus_core.redpanda_traffic_samples (sampled_at);

CREATE TABLE IF NOT EXISTS octopus_core.mv_wireless_heatmap (
  location_id     VARCHAR(128) NOT NULL,
  event_count     BIGINT NOT NULL DEFAULT 0,
  avg_signal_dbm  DECIMAL(10,4) DEFAULT NULL,
  unique_devices  BIGINT NOT NULL DEFAULT 0,
  last_seen_at    timestamptz DEFAULT NULL,
  projection_run_id uuid NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (location_id)
);

CREATE INDEX IF NOT EXISTS mv_wireless_heatmap_events_idx ON octopus_core.mv_wireless_heatmap (event_count);
CREATE INDEX IF NOT EXISTS mv_wireless_heatmap_seen_idx ON octopus_core.mv_wireless_heatmap (last_seen_at);

CREATE TABLE IF NOT EXISTS octopus_core.v_wireless_device_inventory (
  inventory_key        VARCHAR(17) NOT NULL,
  source_mac           VARCHAR(17) NOT NULL,
  first_occurred_at    timestamptz NOT NULL,
  last_occurred_at     timestamptz NOT NULL,
  first_seen           timestamptz NOT NULL,
  last_seen            timestamptz NOT NULL,
  observed_at          timestamptz NOT NULL,
  occurrence_count     BIGINT NOT NULL DEFAULT 0,
  frame_count          BIGINT NOT NULL DEFAULT 0,
  location_id          VARCHAR(128) DEFAULT NULL,
  sensor_id            VARCHAR(64) DEFAULT NULL,
  bssid                VARCHAR(17) DEFAULT NULL,
  destination_bssid    VARCHAR(17) DEFAULT NULL,
  ssid                 VARCHAR(256) DEFAULT NULL,
  signal_dbm           VARCHAR(32) DEFAULT NULL,
  username             VARCHAR(255) DEFAULT NULL,
  ip_addresses         TEXT DEFAULT NULL,
  hostnames            TEXT DEFAULT NULL,
  services             TEXT DEFAULT NULL,
  dns_names            TEXT DEFAULT NULL,
  protected_frame_count BIGINT NOT NULL DEFAULT 0,
  open_frame_count     BIGINT NOT NULL DEFAULT 0,
  wps_device_name      VARCHAR(255) DEFAULT NULL,
  wps_manufacturer     VARCHAR(255) DEFAULT NULL,
  wps_model_name       VARCHAR(255) DEFAULT NULL,
  device_fingerprint   VARCHAR(255) DEFAULT NULL,
  device_id            VARCHAR(17) DEFAULT NULL,
  display_name         VARCHAR(255) DEFAULT NULL,
  registered_username  VARCHAR(255) DEFAULT NULL,
  os_hint              VARCHAR(128) DEFAULT NULL,
  hostname             VARCHAR(253) DEFAULT NULL,
  projection_run_id    uuid NOT NULL,
  updated_at           timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (inventory_key)
);

CREATE INDEX IF NOT EXISTS v_wireless_device_inventory_seen_idx ON octopus_core.v_wireless_device_inventory (last_seen);
CREATE INDEX IF NOT EXISTS v_wireless_device_inventory_location_idx ON octopus_core.v_wireless_device_inventory (location_id, last_seen);

CREATE TABLE IF NOT EXISTS octopus_core.v_wireless_shadow_alerts (
  alert_id          VARCHAR(17) NOT NULL,
  dedupe_key        VARCHAR(17) NOT NULL,
  source_mac        VARCHAR(17) NOT NULL,
  first_occurred_at timestamptz NOT NULL,
  last_occurred_at  timestamptz NOT NULL,
  observed_at       timestamptz NOT NULL,
  occurrence_count  BIGINT NOT NULL DEFAULT 1,
  destination_bssid VARCHAR(17) DEFAULT NULL,
  ssid              VARCHAR(256) DEFAULT NULL,
  sensor_id         VARCHAR(64) DEFAULT NULL,
  location_id       VARCHAR(128) DEFAULT NULL,
  signal_dbm        INT DEFAULT NULL,
  reason            VARCHAR(255) NOT NULL,
  evidence          jsonb NOT NULL,
  resolved_at       timestamptz DEFAULT NULL,
  created_at        timestamptz NOT NULL,
  updated_at        timestamptz NOT NULL,
  projection_run_id uuid NOT NULL,
  PRIMARY KEY (alert_id),
  CONSTRAINT v_wireless_shadow_alerts_dedupe_uq UNIQUE (dedupe_key)
);

CREATE INDEX IF NOT EXISTS v_wireless_shadow_alerts_open_idx ON octopus_core.v_wireless_shadow_alerts (resolved_at, last_occurred_at);

CREATE TABLE IF NOT EXISTS octopus_core.v_sync_plane_health (
  projection_key                    VARCHAR(64) NOT NULL DEFAULT 'current',
  measured_at                       timestamptz NOT NULL,
  wireless_events_24h_count         BIGINT NOT NULL DEFAULT 0,
  wireless_last_observed_at         timestamptz DEFAULT NULL,
  wireless_ingest_pending_count     BIGINT NOT NULL DEFAULT 0,
  wireless_ingest_processing_count  BIGINT NOT NULL DEFAULT 0,
  wireless_ingest_batched_count     BIGINT NOT NULL DEFAULT 0,
  wireless_ingest_failed_count      BIGINT NOT NULL DEFAULT 0,
  wireless_ingest_total_count       BIGINT NOT NULL DEFAULT 0,
  ingest_pending_count              BIGINT NOT NULL DEFAULT 0,
  ingest_processing_count           BIGINT NOT NULL DEFAULT 0,
  ingest_batched_count              BIGINT NOT NULL DEFAULT 0,
  ingest_failed_count               BIGINT NOT NULL DEFAULT 0,
  ingest_total_count                BIGINT NOT NULL DEFAULT 0,
  batch_pending_count               BIGINT NOT NULL DEFAULT 0,
  batch_processing_count            BIGINT NOT NULL DEFAULT 0,
  batch_dispatched_count            BIGINT NOT NULL DEFAULT 0,
  batch_completed_count             BIGINT NOT NULL DEFAULT 0,
  batch_failed_count                BIGINT NOT NULL DEFAULT 0,
  batch_total_count                 BIGINT NOT NULL DEFAULT 0,
  job_stored_pending_count          BIGINT NOT NULL DEFAULT 0,
  job_stored_running_count          BIGINT NOT NULL DEFAULT 0,
  job_stored_completed_count        BIGINT NOT NULL DEFAULT 0,
  job_stored_failed_count           BIGINT NOT NULL DEFAULT 0,
  job_total_count                   BIGINT NOT NULL DEFAULT 0,
  job_effective_pending_count       BIGINT NOT NULL DEFAULT 0,
  job_effective_running_count       BIGINT NOT NULL DEFAULT 0,
  job_effective_completed_count     BIGINT NOT NULL DEFAULT 0,
  job_effective_failed_count        BIGINT NOT NULL DEFAULT 0,
  job_orphaned_count                BIGINT NOT NULL DEFAULT 0,
  backlog_pending_count             BIGINT NOT NULL DEFAULT 0,
  backlog_failed_count              BIGINT NOT NULL DEFAULT 0,
  open_shadow_it_alert_count        BIGINT NOT NULL DEFAULT 0,
  last_shadow_it_alert_at           timestamptz DEFAULT NULL,
  wireless_cursor_value             TEXT DEFAULT NULL,
  wireless_cursor_updated_at        timestamptz DEFAULT NULL,
  projection_run_id                 uuid NOT NULL,
  updated_at                        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (projection_key)
);
