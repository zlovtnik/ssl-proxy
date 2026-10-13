-- Bounded retention and observability queries must not scan all historical runs.
CREATE INDEX IF NOT EXISTS dq_runs_retention_idx
  ON octopus_core.dq_runs (installation_id, namespace, completed_at, run_id)
  WHERE status IN ('succeeded','failed','cancelled');
CREATE INDEX IF NOT EXISTS dq_runs_created_idx
  ON octopus_core.dq_runs (installation_id, namespace, created_at);
CREATE INDEX IF NOT EXISTS dq_artifacts_retention_idx
  ON octopus_core.dq_artifacts (installation_id, namespace, retained_until, artifact_id)
  WHERE retained_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS dq_artifacts_unclosed_idx
  ON octopus_core.dq_artifacts (run_id) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS dq_artifacts_object_version_idx
  ON octopus_core.dq_artifacts ((reference->>'uri'), (reference->>'version_id'));
CREATE INDEX IF NOT EXISTS dq_receipts_retention_idx
  ON octopus_core.dq_receipts (installation_id, namespace, received_at);
CREATE INDEX IF NOT EXISTS dq_audit_retention_idx
  ON octopus_core.dq_audit (installation_id, namespace, created_at);
CREATE INDEX IF NOT EXISTS dq_outbox_run_status_idx
  ON octopus_core.dq_outbox ((payload->>'run_id'), status);
CREATE INDEX IF NOT EXISTS dq_outbox_retention_idx
  ON octopus_core.dq_outbox (published_at, outbox_id) WHERE status='published';
CREATE INDEX IF NOT EXISTS dq_attempts_finished_idx
  ON octopus_core.dq_attempts (finished_at) WHERE finished_at IS NOT NULL;
