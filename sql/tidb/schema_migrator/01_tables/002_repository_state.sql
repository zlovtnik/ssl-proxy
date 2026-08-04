-- object: schema_migrator_repository_state
-- depends_on: schema_migrator_schema_control

USE schema_migrator;

CREATE TABLE IF NOT EXISTS targets (
  id                  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  label               VARCHAR(255) NOT NULL,
  app_name            VARCHAR(255) NOT NULL,
  environment         VARCHAR(128) NOT NULL,
  jdbc_url            TEXT NOT NULL,
  db_kind             VARCHAR(32) NOT NULL,
  created_at          DATETIME(6) NOT NULL,
  updated_at          DATETIME(6) NOT NULL,
  repo_url            TEXT NOT NULL,
  repo_branch         VARCHAR(255) NOT NULL,
  repo_sql_path       VARCHAR(1024) NOT NULL,
  last_synced_commit  VARCHAR(128) DEFAULT NULL,
  last_synced_at      DATETIME(6) DEFAULT NULL,
  password_ciphertext BLOB DEFAULT NULL,
  password_iv         BLOB DEFAULT NULL,
  PRIMARY KEY (id),
  KEY targets_created_at_idx (created_at),
  CONSTRAINT targets_password_complete_ck CHECK (
    (password_ciphertext IS NULL AND password_iv IS NULL)
    OR
    (password_ciphertext IS NOT NULL AND password_iv IS NOT NULL)
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sql_files (
  target_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  path        VARCHAR(512) NOT NULL,
  folder      VARCHAR(128) NOT NULL,
  filename    VARCHAR(255) NOT NULL,
  content     LONGBLOB NOT NULL,
  sha256      CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  uploaded_at DATETIME(6) NOT NULL,
  PRIMARY KEY (target_id, path),
  KEY sql_files_folder_filename_idx (target_id, folder, filename)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS patches (
  id                 CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  version            VARCHAR(128) NOT NULL,
  label              VARCHAR(255) NOT NULL,
  status             VARCHAR(32) NOT NULL,
  applied_at         DATETIME(6) DEFAULT NULL,
  source_snapshot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY patches_target_version_uq (target_id, version),
  KEY patches_status_idx (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS patch_scripts (
  id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  patch_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  script_order INT NOT NULL,
  filename     VARCHAR(255) NOT NULL,
  checksum     CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error        JSON DEFAULT NULL,
  duration_ms  BIGINT DEFAULT NULL,
  content      LONGBLOB NOT NULL,
  created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY patch_scripts_order_uq (patch_id, script_order),
  KEY patch_scripts_status_idx (patch_id, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS snapshots (
  id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  label      VARCHAR(255) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  file_count INT NOT NULL,
  PRIMARY KEY (id),
  KEY snapshots_target_created_idx (target_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS snapshot_files (
  snapshot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  path        VARCHAR(512) NOT NULL,
  folder      VARCHAR(128) NOT NULL,
  filename    VARCHAR(255) NOT NULL,
  sha256      CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  content     LONGBLOB NOT NULL,
  uploaded_at DATETIME(6) NOT NULL,
  size_bytes  BIGINT NOT NULL,
  PRIMARY KEY (snapshot_id, path)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS repository_state (
  target_id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  last_scanned_commit VARCHAR(128) DEFAULT NULL,
  manifest_sha256    CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  file_count         INT NOT NULL DEFAULT 0,
  status             VARCHAR(32) NOT NULL DEFAULT 'empty',
  last_error         TEXT DEFAULT NULL,
  scanned_at         DATETIME(6) DEFAULT NULL,
  updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (target_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS keycloak_config (
  id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  enabled    TINYINT(1) NOT NULL,
  issuer     TEXT DEFAULT NULL,
  jwks_uri   TEXT DEFAULT NULL,
  client_id  VARCHAR(255) DEFAULT NULL,
  audience   VARCHAR(255) DEFAULT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB;
