-- object: schema_migrator_schema_control
-- depends_on: schema_migrator_database

USE schema_migrator;

CREATE TABLE IF NOT EXISTS state_schema_migrations (
  version    VARCHAR(128) NOT NULL,
  checksum   CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  applied_by VARCHAR(128) NOT NULL DEFAULT 'schema-migrator',
  PRIMARY KEY (version)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS schema_readiness (
  domain            VARCHAR(64) NOT NULL,
  required_version  VARCHAR(64) NOT NULL,
  applied_version   VARCHAR(64) DEFAULT NULL,
  required_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  applied_checksum  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  ready             TINYINT(1) NOT NULL DEFAULT 0,
  details           JSON DEFAULT NULL,
  checked_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (domain),
  CONSTRAINT schema_migrator_schema_ready_ck CHECK (
    ready = 0 OR (
      applied_version = required_version
      AND applied_checksum = required_checksum
    )
  )
) ENGINE=InnoDB;

INSERT INTO schema_readiness (
  domain, required_version, applied_version, required_checksum,
  applied_checksum, ready, details
) VALUES (
  'schema_migrator',
  '001',
  NULL,
  '0000000000000000000000000000000000000000000000000000000000000000',
  NULL,
  0,
  JSON_OBJECT('state', 'awaiting-manifest-verification')
) ON DUPLICATE KEY UPDATE domain = VALUES(domain);
