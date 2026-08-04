-- object: atheros_search_schema_manifest
-- depends_on: atheros_search_database

USE atheros_search;

CREATE TABLE IF NOT EXISTS schema_manifest (
  component       VARCHAR(64) NOT NULL,
  manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  schema_ready    TINYINT(1) NOT NULL DEFAULT 0,
  vector_ready    TINYINT(1) NOT NULL DEFAULT 0,
  applied_at      DATETIME(6) DEFAULT NULL,
  updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  details         JSON DEFAULT NULL,
  PRIMARY KEY (component)
) ENGINE=InnoDB;

INSERT INTO schema_manifest (
  component, manifest_sha256, schema_ready, vector_ready, applied_at, details
) VALUES (
  'atheros-search',
  '0000000000000000000000000000000000000000000000000000000000000000',
  0,
  0,
  NULL,
  JSON_OBJECT('state', 'awaiting-manifest-verification')
) ON DUPLICATE KEY UPDATE component = VALUES(component);

CREATE TABLE IF NOT EXISTS schema_revisions (
  migration_id   VARCHAR(128) NOT NULL,
  content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  applied_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  applied_by     VARCHAR(128) NOT NULL,
  PRIMARY KEY (migration_id)
) ENGINE=InnoDB;
