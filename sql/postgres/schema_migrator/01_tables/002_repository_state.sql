-- object: schema_migrator_repository_state
-- depends_on: schema_migrator_schema_control

CREATE TABLE IF NOT EXISTS schema_migrator.targets (
  id                  uuid NOT NULL,
  label               VARCHAR(255) NOT NULL,
  app_name            VARCHAR(255) NOT NULL,
  environment         VARCHAR(128) NOT NULL,
  jdbc_url            TEXT NOT NULL,
  db_kind             VARCHAR(32) NOT NULL,
  created_at          timestamptz NOT NULL,
  updated_at          timestamptz NOT NULL,
  repo_url            TEXT NOT NULL,
  repo_branch         VARCHAR(255) NOT NULL,
  repo_sql_path       VARCHAR(1024) NOT NULL,
  last_synced_commit  VARCHAR(128) DEFAULT NULL,
  last_synced_at      timestamptz DEFAULT NULL,
  password_ciphertext bytea DEFAULT NULL,
  password_iv         bytea DEFAULT NULL,
  PRIMARY KEY (id),
  CONSTRAINT targets_password_complete_ck CHECK (
    (password_ciphertext IS NULL AND password_iv IS NULL)
    OR
    (password_ciphertext IS NOT NULL AND password_iv IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS targets_created_at_idx ON schema_migrator.targets (created_at);

CREATE TABLE IF NOT EXISTS schema_migrator.sql_files (
  target_id   uuid NOT NULL,
  path        VARCHAR(512) NOT NULL,
  folder      VARCHAR(128) NOT NULL,
  filename    VARCHAR(255) NOT NULL,
  content     bytea NOT NULL,
  sha256      char(64) NOT NULL,
  uploaded_at timestamptz NOT NULL,
  PRIMARY KEY (target_id, path)
);

CREATE INDEX IF NOT EXISTS sql_files_folder_filename_idx ON schema_migrator.sql_files (target_id, folder, filename);

CREATE TABLE IF NOT EXISTS schema_migrator.patches (
  id                 uuid NOT NULL,
  target_id          uuid NOT NULL,
  version            VARCHAR(128) NOT NULL,
  label              VARCHAR(255) NOT NULL,
  status             VARCHAR(32) NOT NULL,
  applied_at         timestamptz DEFAULT NULL,
  source_snapshot_id uuid DEFAULT NULL,
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT patches_target_version_uq UNIQUE (target_id, version)
);

CREATE INDEX IF NOT EXISTS patches_status_idx ON schema_migrator.patches (status);

CREATE TABLE IF NOT EXISTS schema_migrator.patch_scripts (
  id           uuid NOT NULL,
  patch_id     uuid NOT NULL,
  script_order INT NOT NULL,
  filename     VARCHAR(255) NOT NULL,
  checksum     char(64) NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error        jsonb DEFAULT NULL,
  duration_ms  BIGINT DEFAULT NULL,
  content      bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT patch_scripts_order_uq UNIQUE (patch_id, script_order)
);

CREATE INDEX IF NOT EXISTS patch_scripts_status_idx ON schema_migrator.patch_scripts (patch_id, status);

CREATE TABLE IF NOT EXISTS schema_migrator.snapshots (
  id         uuid NOT NULL,
  target_id  uuid NOT NULL,
  label      VARCHAR(255) NOT NULL,
  created_at timestamptz NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  file_count INT NOT NULL,
  PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS snapshots_target_created_idx ON schema_migrator.snapshots (target_id, created_at);

CREATE TABLE IF NOT EXISTS schema_migrator.snapshot_files (
  snapshot_id uuid NOT NULL,
  path        VARCHAR(512) NOT NULL,
  folder      VARCHAR(128) NOT NULL,
  filename    VARCHAR(255) NOT NULL,
  sha256      char(64) NOT NULL,
  content     bytea NOT NULL,
  uploaded_at timestamptz NOT NULL,
  size_bytes  BIGINT NOT NULL,
  PRIMARY KEY (snapshot_id, path)
);

CREATE TABLE IF NOT EXISTS schema_migrator.repository_state (
  target_id          uuid NOT NULL,
  last_scanned_commit VARCHAR(128) DEFAULT NULL,
  manifest_sha256    char(64) DEFAULT NULL,
  file_count         INT NOT NULL DEFAULT 0,
  status             VARCHAR(32) NOT NULL DEFAULT 'empty',
  last_error         TEXT DEFAULT NULL,
  scanned_at         timestamptz DEFAULT NULL,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (target_id)
);

CREATE TABLE IF NOT EXISTS schema_migrator.keycloak_config (
  id         uuid NOT NULL,
  enabled    boolean NOT NULL,
  issuer     TEXT DEFAULT NULL,
  jwks_uri   TEXT DEFAULT NULL,
  client_id  VARCHAR(255) DEFAULT NULL,
  audience   VARCHAR(255) DEFAULT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (id)
);
