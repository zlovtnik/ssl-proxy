-- object: integration_console_schema_control
-- depends_on: integration_console_database

USE integration_console;

CREATE TABLE IF NOT EXISTS schema_revisions (
  migration_id   VARCHAR(128) NOT NULL,
  content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  applied_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  applied_by     VARCHAR(128) NOT NULL,
  PRIMARY KEY (migration_id)
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
  CONSTRAINT integration_console_schema_ready_ck CHECK (
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
  'integration_console',
  '001',
  NULL,
  '0000000000000000000000000000000000000000000000000000000000000000',
  NULL,
  0,
  JSON_OBJECT('state', 'awaiting-manifest-verification')
) ON DUPLICATE KEY UPDATE domain = VALUES(domain);

-- Rails owns neither canonical DDL ordering nor checksums, but these adapter
-- compatibility tables prevent Active Record from replaying PostgreSQL history.
CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(255) NOT NULL,
  PRIMARY KEY (version)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ar_internal_metadata (
  `key`      VARCHAR(255) NOT NULL,
  value      VARCHAR(255) DEFAULT NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB;
