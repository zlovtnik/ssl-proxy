-- object: octopus_core_outbox_lease_lookup
-- depends_on: octopus_core_processor_leases_and_outbox
-- The claim transaction stamps a fresh owner/token pair, then reads the
-- claimed row through this index without scanning the outbox backlog.

USE octopus_core;

SET @outbox_lease_lookup_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = 'octopus_core'
    AND table_name = 'outbox_events'
    AND index_name = 'outbox_events_lease_lookup_idx'
);

SET @outbox_lease_lookup_ddl = IF(
  @outbox_lease_lookup_exists = 0,
  'CREATE INDEX outbox_events_lease_lookup_idx ON outbox_events (owner_id, lease_token)',
  'SELECT 1'
);

PREPARE outbox_lease_lookup_stmt FROM @outbox_lease_lookup_ddl;
EXECUTE outbox_lease_lookup_stmt;
DEALLOCATE PREPARE outbox_lease_lookup_stmt;
