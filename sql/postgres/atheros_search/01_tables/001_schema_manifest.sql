-- object: atheros_search_schema_control
-- depends_on: atheros_search_schema

CREATE TABLE IF NOT EXISTS atheros_search.schema_readiness (
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
      applied_version IS NOT NULL
      AND applied_checksum IS NOT NULL
      AND applied_version = required_version
      AND applied_checksum = required_checksum
    )
  )
);

INSERT INTO atheros_search.schema_readiness (
  domain, required_version, required_checksum, ready, details
) VALUES (
  'atheros_search',
  '002',
  '0000000000000000000000000000000000000000000000000000000000000000',
  false,
  jsonb_build_object('state', 'awaiting-manifest-verification')
) ON CONFLICT (domain) DO NOTHING;
