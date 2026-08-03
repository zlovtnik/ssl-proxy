-- object: octopus_core_retention_and_reconciliation_runs
-- depends_on: octopus_core_processor_leases_and_outbox
-- Append-only run evidence for maintenance processors. Authoritative ingestion
-- evidence is never a reconciliation repair target.

USE octopus_core;

CREATE TABLE IF NOT EXISTS retention_runs (
  run_id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  policy_name     VARCHAR(128) NOT NULL,
  target_table    VARCHAR(128) NOT NULL,
  cutoff_at       DATETIME(6) NOT NULL,
  status          VARCHAR(32) NOT NULL,
  rows_selected   BIGINT NOT NULL DEFAULT 0,
  rows_archived   BIGINT NOT NULL DEFAULT 0,
  rows_deleted    BIGINT NOT NULL DEFAULT 0,
  lease_owner_id  VARCHAR(128) NOT NULL,
  lease_fence     BIGINT NOT NULL,
  error_text      TEXT DEFAULT NULL,
  started_at      DATETIME(6) NOT NULL,
  finished_at     DATETIME(6) DEFAULT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (run_id),
  KEY retention_runs_candidate_idx (policy_name, status, started_at),
  CONSTRAINT retention_runs_status_ck CHECK (
    status IN ('running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT retention_runs_counts_ck CHECK (
    rows_selected >= 0 AND rows_archived >= 0 AND rows_deleted >= 0
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS reconciliation_findings (
  finding_id       CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  processor_name   VARCHAR(128) NOT NULL,
  entity_type      VARCHAR(128) NOT NULL,
  entity_key       VARCHAR(255) NOT NULL,
  projection_version BIGINT NOT NULL DEFAULT 1,
  finding_type     VARCHAR(64) NOT NULL,
  expected_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  actual_sha256    CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'open',
  repair_action    VARCHAR(64) DEFAULT NULL,
  details          JSON NOT NULL,
  first_seen_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  resolved_at      DATETIME(6) DEFAULT NULL,
  PRIMARY KEY (finding_id),
  UNIQUE KEY reconciliation_findings_identity_uq (
    processor_name, entity_type, entity_key, projection_version, finding_type
  ),
  KEY reconciliation_findings_scan_idx (processor_name, status, last_seen_at),
  CONSTRAINT reconciliation_findings_status_ck CHECK (
    status IN ('open', 'repairing', 'resolved', 'ignored')
  )
) ENGINE=InnoDB;
