-- object: octopus_core_shadow_alert_projection_run_id
-- depends_on: octopus_core_wireless_state

USE octopus_core;

-- Add projection_run_id to wireless_shadow_alerts to support shadow alert generation.
-- The ProjectionSql.generateShadowAlerts query writes this column but the base table
-- was missing it, causing SQLSyntaxErrorException at runtime.

SET @shadow_alert_projection_run_id_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = 'octopus_core'
    AND table_name = 'wireless_shadow_alerts'
    AND column_name = 'projection_run_id'
);

SET @shadow_alert_projection_run_id_ddl = IF(
  @shadow_alert_projection_run_id_exists = 0,
  'ALTER TABLE wireless_shadow_alerts ADD COLUMN projection_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin AFTER updated_at',
  'SELECT 1'
);

PREPARE shadow_alert_projection_run_id_stmt
  FROM @shadow_alert_projection_run_id_ddl;
EXECUTE shadow_alert_projection_run_id_stmt;
DEALLOCATE PREPARE shadow_alert_projection_run_id_stmt;
