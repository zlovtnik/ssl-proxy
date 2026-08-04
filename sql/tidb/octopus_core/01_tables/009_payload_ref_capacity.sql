-- object: octopus_core_payload_ref_capacity
-- depends_on: octopus_core_ingestion_evidence
-- Inline base64 payload references can exceed the 65,535-byte TEXT limit even
-- when the original payload is within the proxy's accepted body-size limit.

USE octopus_core;

ALTER TABLE sync_events
  MODIFY COLUMN payload_ref MEDIUMTEXT NOT NULL;

ALTER TABLE sync_batches
  MODIFY COLUMN payload_ref MEDIUMTEXT NOT NULL;
