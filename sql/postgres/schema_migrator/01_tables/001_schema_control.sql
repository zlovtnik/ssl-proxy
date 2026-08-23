-- object: schema_migrator_schema_control
-- depends_on: schema_migrator_database

CREATE TABLE IF NOT EXISTS schema_migrator.state_schema_migrations (
  version    VARCHAR(128) NOT NULL,
  checksum   char(64) NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_by VARCHAR(128) NOT NULL DEFAULT 'schema-migrator',
  PRIMARY KEY (version)
);

CREATE TABLE IF NOT EXISTS schema_migrator.schema_readiness (
  domain            VARCHAR(64) NOT NULL,
  required_version  VARCHAR(64) NOT NULL,
  applied_version   VARCHAR(64) DEFAULT NULL,
  required_checksum char(64) NOT NULL,
  applied_checksum  char(64) DEFAULT NULL,
  ready             boolean NOT NULL DEFAULT false,
  details           jsonb DEFAULT NULL,
  checked_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (domain),
  CONSTRAINT schema_migrator_schema_ready_ck CHECK (
    ready = false OR (
      applied_version = required_version
      AND applied_checksum = required_checksum
    )
  )
);

INSERT INTO schema_migrator.schema_readiness (
  domain, required_version, applied_version, required_checksum,
  applied_checksum, ready, details
) VALUES (
  'schema_migrator',
  '001',
  NULL,
  '0000000000000000000000000000000000000000000000000000000000000000',
  NULL,
  false,
  jsonb_build_object('state', 'awaiting-manifest-verification')
) ON CONFLICT DO NOTHING;
