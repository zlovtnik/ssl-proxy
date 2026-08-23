-- object: octopus_core_outbox_lease_lookup
-- depends_on: octopus_core_processor_leases_and_outbox
-- The claim transaction stamps a fresh owner/token pair, then reads the
-- claimed row through this index without scanning the outbox backlog.

CREATE INDEX IF NOT EXISTS outbox_events_lease_lookup_idx
  ON octopus_core.outbox_events (owner_id, lease_token);
