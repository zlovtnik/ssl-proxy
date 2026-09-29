-- object: octopus_core_wireless_frames_cooccurrence_idx
-- depends_on: octopus_core_projection_dispatch_indexes
--
-- The identity graph projection pairs two wireless frames that share a BSSID
-- inside a ten minute window and groups them by unordered MAC pair. The
-- existing wireless_frames_bssid_idx (bssid, observed_at) serves the join but
-- leaves the planner sorting an estimated 3.17 billion rows per side, which
-- spilled tens of gigabytes of temporary files. Indexing source_mac, bssid and
-- observed_at lets the group-by key be produced in order instead of sorted.

CREATE INDEX IF NOT EXISTS wireless_frames_cooccurrence_idx
  ON octopus_core.wireless_frames (source_mac, bssid, observed_at)
  WHERE source_mac IS NOT NULL AND bssid IS NOT NULL;
