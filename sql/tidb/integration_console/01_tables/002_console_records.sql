-- object: integration_console_records
-- depends_on: integration_console_schema_control

USE integration_console;

CREATE TABLE IF NOT EXISTS integration_configs (
  id               CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  name             VARCHAR(255) NOT NULL,
  slug             VARCHAR(128) NOT NULL,
  source_type      VARCHAR(64) NOT NULL,
  destination_type VARCHAR(64) NOT NULL,
  stream_name      VARCHAR(255) DEFAULT NULL,
  enabled          TINYINT(1) NOT NULL DEFAULT 1,
  schedule_cron    VARCHAR(255) DEFAULT NULL,
  params           JSON NOT NULL,
  param_schema     JSON NOT NULL,
  cursor_field     VARCHAR(128) DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY integration_configs_slug_uq (slug),
  KEY integration_configs_enabled_idx (enabled)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS integration_runs (
  id                    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  integration_config_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  sync_job_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  triggered_by          VARCHAR(32) NOT NULL DEFAULT 'schedule',
  status                VARCHAR(32) NOT NULL DEFAULT 'pending',
  range_type            VARCHAR(32) NOT NULL DEFAULT 'cursor',
  from_value            TEXT DEFAULT NULL,
  to_value              TEXT DEFAULT NULL,
  params_snapshot       JSON NOT NULL,
  error_summary         TEXT DEFAULT NULL,
  started_at            DATETIME(6) DEFAULT NULL,
  finished_at           DATETIME(6) DEFAULT NULL,
  created_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY integration_runs_config_created_idx (integration_config_id, created_at),
  KEY integration_runs_config_trigger_idx (
    integration_config_id, triggered_by, created_at
  ),
  KEY integration_runs_config_status_idx (
    integration_config_id, status, created_at
  ),
  KEY integration_runs_status_idx (status, created_at),
  KEY integration_runs_sync_job_idx (sync_job_id),
  CONSTRAINT integration_runs_config_fk FOREIGN KEY (integration_config_id)
    REFERENCES integration_configs (id) ON DELETE RESTRICT,
  CONSTRAINT integration_runs_triggered_by_ck CHECK (
    triggered_by IN ('schedule', 'manual', 'replay')
  ),
  CONSTRAINT integration_runs_status_ck CHECK (
    status IN ('pending', 'running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT integration_runs_range_type_ck CHECK (
    range_type IN ('cursor', 'datetime')
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_windows (
  id          BIGINT NOT NULL AUTO_INCREMENT,
  location_id VARCHAR(128) NOT NULL,
  timezone    VARCHAR(64) NOT NULL DEFAULT 'America/New_York',
  days        VARCHAR(64) DEFAULT NULL,
  start_time  TIME(6) DEFAULT NULL,
  end_time    TIME(6) DEFAULT NULL,
  enabled     TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY audit_windows_location_uq (location_id)
) ENGINE=InnoDB;
