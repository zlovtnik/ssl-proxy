-- object: octopus_core_shadow_alert_projection_run_id
-- depends_on: octopus_core_wireless_state

-- Add projection_run_id to wireless_shadow_alerts to support shadow alert generation.
-- The ProjectionSql.generateShadowAlerts query writes this column but the base table
-- was missing it, causing SQLSyntaxErrorException at runtime.

ALTER TABLE octopus_core.wireless_shadow_alerts
  ADD COLUMN IF NOT EXISTS projection_run_id uuid;
