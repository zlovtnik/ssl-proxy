-- object: octopus_core_proxy_search_indexes
-- depends_on: octopus_core_retention_and_reconciliation_runs
-- Append-only indexes for proxy event document preparation and API filters.

CREATE INDEX IF NOT EXISTS proxy_events_blocked_time_idx
  ON octopus_core.proxy_events (event_time DESC, event_id)
  WHERE blocked = TRUE;

CREATE INDEX IF NOT EXISTS proxy_events_device_time_idx
  ON octopus_core.proxy_events (registered_device_id, event_time DESC);

CREATE INDEX IF NOT EXISTS proxy_events_event_type_time_idx
  ON octopus_core.proxy_events (event_type, event_time DESC, event_id);
