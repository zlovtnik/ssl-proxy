-- object: octopus_core_payload_ref_capacity
-- depends_on: octopus_core_ingestion_evidence
-- Inline base64 payload references can exceed the 65,535-byte TEXT limit even
-- when the original payload is within the proxy's accepted body-size limit.

ALTER TABLE octopus_core.sync_events
  ALTER COLUMN payload_ref TYPE text;

ALTER TABLE octopus_core.sync_batches
  ALTER COLUMN payload_ref TYPE text;
