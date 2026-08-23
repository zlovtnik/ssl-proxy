-- object: octopus_core_adjacent_mac_hint_capacity
-- depends_on: octopus_core_ingestion_evidence, octopus_core_wireless_state
-- A hint contains comma-separated "mac1~mac2" pairs, so even one valid pair
-- exceeds the 17-character width of an individual MAC address.

ALTER TABLE octopus_core.sync_events
  ALTER COLUMN adjacent_mac_hint TYPE VARCHAR(512);

ALTER TABLE octopus_core.wireless_frame_security
  ALTER COLUMN adjacent_mac_hint TYPE VARCHAR(512);
