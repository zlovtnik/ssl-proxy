-- object: octopus_core_projection_input_markers
-- depends_on: octopus_core_retention_and_reconciliation_runs
-- Durable row-level markers make replayed periodic projections idempotent.

USE octopus_core;

CREATE TABLE IF NOT EXISTS wireless_inventory_projection_inputs (
  dedupe_key   VARCHAR(255) NOT NULL,
  projected_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key),
  KEY wireless_inventory_projection_inputs_time_idx (projected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wireless_shadow_alert_inputs (
  dedupe_key   VARCHAR(255) NOT NULL,
  source_mac   VARCHAR(17) NOT NULL,
  projected_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (dedupe_key),
  KEY wireless_shadow_alert_inputs_source_idx (source_mac, projected_at)
) ENGINE=InnoDB;
