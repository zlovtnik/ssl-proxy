-- object: octopus_core_projection_dispatch_indexes
-- depends_on: octopus_core_proxy_search_indexes
-- Append-only indexes for wireless frame projection and load dispatch scans.

CREATE INDEX IF NOT EXISTS sync_events_wireless_projection_idx
  ON octopus_core.sync_events (stream_name, observed_at, dedupe_key)
  WHERE payload IS NOT NULL OR payload_archived = TRUE;

CREATE INDEX IF NOT EXISTS wireless_frames_observed_dedupe_idx
  ON octopus_core.wireless_frames (observed_at, dedupe_key);

CREATE INDEX IF NOT EXISTS sync_batches_pending_created_idx
  ON octopus_core.sync_batches (created_at, batch_id)
  WHERE status = 'pending';
