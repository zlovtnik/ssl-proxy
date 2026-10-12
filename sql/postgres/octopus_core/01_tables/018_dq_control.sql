-- DQ has no database clients: Octopus owns its registry, leases and application.
-- Registry dimensions are immutable; hot receipts/audit have no parent FKs.
CREATE TABLE IF NOT EXISTS octopus_core.dq_scope_policies (
  installation_id TEXT NOT NULL, namespace TEXT NOT NULL, authorized_scope TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('disabled','shadow','enabled')), policy_version TEXT NOT NULL,
  PRIMARY KEY (installation_id,namespace,authorized_scope)
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_processor_versions (
  installation_id TEXT NOT NULL, namespace TEXT NOT NULL, processor_id TEXT NOT NULL,
  version TEXT NOT NULL, manifest JSONB NOT NULL, manifest_sha256 TEXT NOT NULL,
  implementation_digest TEXT NOT NULL, parameter_schema_sha256 TEXT NOT NULL,
  policy_version TEXT NOT NULL, registered_by TEXT NOT NULL,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (installation_id, namespace, processor_id, version),
  CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  CHECK (parameter_schema_sha256 ~ '^[0-9a-f]{64}$'),
  CHECK (implementation_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_processors (
  installation_id TEXT NOT NULL, namespace TEXT NOT NULL, processor_id TEXT NOT NULL,
  default_version TEXT NOT NULL,
  PRIMARY KEY (installation_id, namespace, processor_id)
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_runs (
  run_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
  processor_id TEXT NOT NULL, processor_version TEXT NOT NULL,
  authorized_scope TEXT NOT NULL, operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL, request_fingerprint TEXT NOT NULL,
  document JSONB NOT NULL, manifest JSONB NOT NULL,
  policy_version TEXT NOT NULL, execution_mode TEXT NOT NULL CHECK (execution_mode IN ('shadow','enabled')),
  status TEXT NOT NULL CHECK (status IN ('queued','preparing','running','applying','retrying','succeeded','failed','cancelled')),
  state_revision BIGINT NOT NULL DEFAULT 1, fence BIGINT NOT NULL DEFAULT 0,
  input_refs JSONB NOT NULL DEFAULT '[]', output_refs JSONB NOT NULL DEFAULT '[]',
  source_revision_digest TEXT NOT NULL DEFAULT '', current_attempt_id TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
  preparation_attempts INTEGER NOT NULL DEFAULT 0,
  application_attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  work_owner TEXT, work_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, deadline_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ, projection_applied BOOLEAN NOT NULL DEFAULT FALSE,
  summary JSONB, error_code TEXT,
  UNIQUE (installation_id, namespace, idempotency_key)
);
CREATE INDEX IF NOT EXISTS dq_runs_work_idx ON octopus_core.dq_runs (status,next_attempt_at,created_at,run_id)
  WHERE status IN ('queued','preparing','retrying','applying');
CREATE INDEX IF NOT EXISTS dq_runs_scope_idx ON octopus_core.dq_runs (installation_id,namespace,authorized_scope,status);
CREATE TABLE IF NOT EXISTS octopus_core.dq_workers (
  worker_instance_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
  processor_id TEXT NOT NULL, processor_version TEXT NOT NULL, implementation_digest TEXT NOT NULL,
  address TEXT NOT NULL, concurrency INTEGER NOT NULL CHECK (concurrency BETWEEN 1 AND 256),
  ready BOOLEAN NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_attempts (
  attempt_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES octopus_core.dq_runs(run_id),
  attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 5),
  worker_instance_id TEXT NOT NULL, worker_slot INTEGER NOT NULL CHECK (worker_slot >= 0),
  lease_token TEXT NOT NULL, fence BIGINT NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('reserved','accepted','running','applying','succeeded','failed','expired','cancelled')),
  started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  report_sequence BIGINT NOT NULL DEFAULT -1,
  UNIQUE (run_id,attempt_number)
);
CREATE UNIQUE INDEX IF NOT EXISTS dq_attempts_slot_idx ON octopus_core.dq_attempts (worker_instance_id,worker_slot)
  WHERE status IN ('reserved','accepted','running');
CREATE INDEX IF NOT EXISTS dq_attempts_expiry_idx ON octopus_core.dq_attempts (lease_expires_at)
  WHERE status IN ('reserved','accepted','running','applying');
CREATE TABLE IF NOT EXISTS octopus_core.dq_receipts (
  consumer_group TEXT NOT NULL, topic TEXT NOT NULL, partition_id INTEGER NOT NULL CHECK (partition_id >= 0),
  offset_id BIGINT NOT NULL CHECK (offset_id >= 0), event_id TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  installation_id TEXT NOT NULL, namespace TEXT NOT NULL, envelope JSONB,
  quarantine_reason TEXT, received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (consumer_group,topic,partition_id,offset_id)
);
CREATE INDEX IF NOT EXISTS dq_receipts_event_idx ON octopus_core.dq_receipts (event_id,payload_sha256);
CREATE TABLE IF NOT EXISTS octopus_core.dq_audit (
  audit_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, run_id TEXT, details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_outbox (
  outbox_id TEXT PRIMARY KEY, topic TEXT NOT NULL, message_key TEXT NOT NULL, payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','published')),
  owner TEXT, token TEXT, fence BIGINT NOT NULL DEFAULT 0, lease_expires_at TIMESTAMPTZ,
  attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at TIMESTAMPTZ,
  CHECK (octet_length(payload::TEXT) <= 65536)
);
CREATE INDEX IF NOT EXISTS dq_outbox_pending_idx ON octopus_core.dq_outbox (next_attempt_at,created_at,outbox_id)
  WHERE status <> 'published';
CREATE TABLE IF NOT EXISTS octopus_core.dq_decision_sources (
  candidate_id TEXT NOT NULL, decision TEXT NOT NULL, decision_revision TEXT NOT NULL,
  run_id TEXT NOT NULL, completed_at TIMESTAMPTZ,
  PRIMARY KEY (candidate_id,decision_revision)
);
CREATE TABLE IF NOT EXISTS octopus_core.dq_artifacts (
  artifact_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, reference JSONB NOT NULL,
  installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at TIMESTAMPTZ, retained_until TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS dq_artifacts_run_idx ON octopus_core.dq_artifacts(run_id);
