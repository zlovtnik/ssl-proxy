-- object: octopus_core_shadow_alert_projection_run_id
-- depends_on: octopus_core_wireless_state

USE octopus_core;

-- Add projection_run_id to wireless_shadow_alerts to support shadow alert generation.
-- The ProjectionSql.generateShadowAlerts query writes this column but the base table
-- was missing it, causing SQLSyntaxErrorException at runtime.

ALTER TABLE wireless_shadow_alerts
  ADD COLUMN projection_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''
  AFTER updated_at;
