-- object: octopus_core_projection_input_markers
-- depends_on: octopus_core_retention_and_reconciliation_runs
-- Durable row-level markers make replayed periodic projections idempotent.

CREATE TABLE IF NOT EXISTS octopus_core.wireless_inventory_projection_inputs (
  dedupe_key   VARCHAR(255) NOT NULL,
  projected_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_inventory_projection_inputs_time_idx ON octopus_core.wireless_inventory_projection_inputs (projected_at);

CREATE TABLE IF NOT EXISTS octopus_core.wireless_shadow_alert_inputs (
  dedupe_key   VARCHAR(255) NOT NULL,
  source_mac   VARCHAR(17) NOT NULL,
  projected_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (dedupe_key)
);

CREATE INDEX IF NOT EXISTS wireless_shadow_alert_inputs_source_idx ON octopus_core.wireless_shadow_alert_inputs (source_mac, projected_at);
