-- object: octopus_core_schema_control
-- depends_on: octopus_core_database

CREATE TABLE IF NOT EXISTS octopus_core.schema_revisions (
  migration_id   VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  applied_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_by     VARCHAR(128) NOT NULL,
  PRIMARY KEY (migration_id)
);

CREATE TABLE IF NOT EXISTS octopus_core.schema_readiness (
  domain            VARCHAR(64) NOT NULL,
  required_version  VARCHAR(64) NOT NULL,
  applied_version   VARCHAR(64) DEFAULT NULL,
  required_checksum char(64) NOT NULL,
  applied_checksum  char(64) DEFAULT NULL,
  ready             boolean NOT NULL DEFAULT false,
  details           jsonb DEFAULT NULL,
  checked_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (domain),
  CONSTRAINT schema_readiness_ready_ck CHECK (
    ready = false OR (
      applied_version = required_version
      AND applied_checksum = required_checksum
    )
  )
);

INSERT INTO octopus_core.schema_readiness (
  domain, required_version, applied_version, required_checksum,
  applied_checksum, ready, details
) VALUES (
  'octopus_core',
  '001',
  NULL,
  '0000000000000000000000000000000000000000000000000000000000000000',
  NULL,
  false,
  jsonb_build_object('state', 'awaiting-manifest-verification')
) ON CONFLICT DO NOTHING;
