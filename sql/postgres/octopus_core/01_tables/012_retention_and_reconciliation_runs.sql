-- object: octopus_core_retention_and_reconciliation_runs
-- depends_on: octopus_core_processor_leases_and_outbox
-- Append-only run evidence for maintenance processors. Authoritative ingestion
-- evidence is never a reconciliation repair target.

CREATE TABLE IF NOT EXISTS octopus_core.retention_runs (
  run_id          uuid NOT NULL,
  policy_name     VARCHAR(128) NOT NULL,
  target_table    VARCHAR(128) NOT NULL,
  cutoff_at       timestamptz NOT NULL,
  status          VARCHAR(32) NOT NULL,
  rows_selected   BIGINT NOT NULL DEFAULT 0,
  rows_archived   BIGINT NOT NULL DEFAULT 0,
  rows_deleted    BIGINT NOT NULL DEFAULT 0,
  lease_owner_id  VARCHAR(128) NOT NULL,
  lease_fence     BIGINT NOT NULL,
  error_text      TEXT DEFAULT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz DEFAULT NULL,
  created_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (run_id),
  CONSTRAINT retention_runs_status_ck CHECK (
    status IN ('running', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT retention_runs_counts_ck CHECK (
    rows_selected >= 0 AND rows_archived >= 0 AND rows_deleted >= 0
  )
);

CREATE INDEX IF NOT EXISTS retention_runs_candidate_idx ON octopus_core.retention_runs (policy_name, status, started_at);

CREATE TABLE IF NOT EXISTS octopus_core.reconciliation_findings (
  finding_id       uuid NOT NULL,
  processor_name   VARCHAR(128) NOT NULL,
  entity_type      VARCHAR(128) NOT NULL,
  entity_key       VARCHAR(255) NOT NULL,
  projection_version BIGINT NOT NULL DEFAULT 1,
  finding_type     VARCHAR(64) NOT NULL,
  expected_sha256  char(64) DEFAULT NULL,
  actual_sha256    char(64) DEFAULT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'open',
  repair_action    VARCHAR(64) DEFAULT NULL,
  details          jsonb NOT NULL,
  first_seen_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at      timestamptz DEFAULT NULL,
  PRIMARY KEY (finding_id),
  CONSTRAINT reconciliation_findings_identity_uq UNIQUE (
    processor_name, entity_type, entity_key, projection_version, finding_type
  ),
  CONSTRAINT reconciliation_findings_status_ck CHECK (
    status IN ('open', 'repairing', 'resolved', 'ignored')
  )
);

CREATE INDEX IF NOT EXISTS reconciliation_findings_scan_idx ON octopus_core.reconciliation_findings (processor_name, status, last_seen_at);
