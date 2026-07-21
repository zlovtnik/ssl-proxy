-- object: integration_console_ui_state
-- depends_on: integration_console_records

USE integration_console;

CREATE TABLE IF NOT EXISTS ui_preferences (
  actor_key   VARCHAR(255) NOT NULL,
  preference_key VARCHAR(128) NOT NULL,
  value       JSON NOT NULL,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (actor_key, preference_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saved_grid_views (
  id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_key   VARCHAR(255) NOT NULL,
  resource    VARCHAR(128) NOT NULL,
  name        VARCHAR(255) NOT NULL,
  definition  JSON NOT NULL,
  is_default  TINYINT(1) NOT NULL DEFAULT 0,
  created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY saved_grid_views_actor_name_uq (actor_key, resource, name),
  KEY saved_grid_views_resource_idx (resource, actor_key)
) ENGINE=InnoDB;
