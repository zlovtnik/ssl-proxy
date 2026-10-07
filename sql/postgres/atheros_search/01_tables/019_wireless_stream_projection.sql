-- object: atheros_search_wireless_stream_projection
-- depends_on: atheros_search_identity_graph
-- Shadow projections are isolated from the legacy frame-derived graph.
CREATE TABLE atheros_search.wireless_topology_nodes
  (LIKE atheros_search.graph_nodes INCLUDING ALL);
CREATE TABLE atheros_search.wireless_topology_edges
  (LIKE atheros_search.graph_edges INCLUDING ALL);
ALTER TABLE atheros_search.wireless_topology_edges
  ADD COLUMN expires_at timestamptz;
CREATE INDEX wireless_topology_edges_expiry_idx
  ON atheros_search.wireless_topology_edges (expires_at) WHERE expires_at IS NOT NULL;

-- Compact telemetry: no frame payload, per-frame detail or enforced fact FK.
CREATE TABLE atheros_search.wireless_observation_summaries (
  summary_id uuid PRIMARY KEY,
  sensor_id varchar(64) NOT NULL,
  bssid varchar(17) NOT NULL,
  source_mac varchar(17) NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  frame_count bigint NOT NULL CHECK (frame_count > 0),
  counters jsonb NOT NULL,
  radio jsonb NOT NULL,
  location_id varchar(128),
  ssid varchar(256),
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at timestamptz NOT NULL,
  UNIQUE (sensor_id, bssid, source_mac, window_start),
  CHECK (window_end = window_start + INTERVAL '5 minutes'),
  CHECK (first_seen <= last_seen),
  CHECK (expires_at = window_end + INTERVAL '7 days')
);
CREATE INDEX wireless_observation_summaries_expiry_idx
  ON atheros_search.wireless_observation_summaries (expires_at, summary_id);
CREATE INDEX wireless_observation_summaries_mac_idx
  ON atheros_search.wireless_observation_summaries (source_mac, window_start);

ALTER TABLE atheros_search.search_documents DROP CONSTRAINT search_documents_kind_ck;
ALTER TABLE atheros_search.search_documents ADD CONSTRAINT search_documents_kind_ck CHECK (
  source_kind IN ('event', 'device', 'behaviour_window', 'frame_sequence',
    'proxy_event', 'proxy_blocked_host_window', 'device_profile', 'ap_profile',
    'identity_summary', 'observation_window')
);
