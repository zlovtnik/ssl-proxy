-- object: octopus_core_adjacent_mac_hint_capacity
-- depends_on: octopus_core_ingestion_evidence, octopus_core_wireless_state
-- A hint contains comma-separated "mac1~mac2" pairs, so even one valid pair
-- exceeds the 17-character width of an individual MAC address.

USE octopus_core;

ALTER TABLE sync_events
  MODIFY COLUMN adjacent_mac_hint VARCHAR(512) DEFAULT NULL;

ALTER TABLE wireless_frame_security
  MODIFY COLUMN adjacent_mac_hint VARCHAR(512) DEFAULT NULL;
