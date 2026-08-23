-- object: atheros_search_schema_manifest
-- depends_on: atheros_search_database

CREATE TABLE IF NOT EXISTS atheros_search.schema_manifest (
  component       VARCHAR(64) NOT NULL,
  manifest_sha256 char(64) NOT NULL,
  schema_ready    boolean NOT NULL DEFAULT false,
  vector_ready    boolean NOT NULL DEFAULT false,
  applied_at      timestamptz DEFAULT NULL,
  updated_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  details         jsonb DEFAULT NULL,
  PRIMARY KEY (component)
);

INSERT INTO atheros_search.schema_manifest (
  component, manifest_sha256, schema_ready, vector_ready, applied_at, details
) VALUES (
  'atheros-search',
  '0000000000000000000000000000000000000000000000000000000000000000',
  false,
  false,
  NULL,
  jsonb_build_object('state', 'awaiting-manifest-verification')
) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS atheros_search.schema_revisions (
  migration_id   VARCHAR(128) NOT NULL,
  content_sha256 char(64) NOT NULL,
  applied_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_by     VARCHAR(128) NOT NULL,
  PRIMARY KEY (migration_id)
);
