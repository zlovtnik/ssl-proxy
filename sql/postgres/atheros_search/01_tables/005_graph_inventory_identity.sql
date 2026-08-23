-- object: atheros_search_graph_inventory_identity
-- depends_on: atheros_search_projection_state

CREATE TABLE IF NOT EXISTS atheros_search.graph_nodes (
  node_id        VARCHAR(255) NOT NULL,
  node_kind      VARCHAR(32) NOT NULL,
  label          VARCHAR(255) DEFAULT NULL,
  node_payload   jsonb NOT NULL,
  location_id    VARCHAR(128) DEFAULT NULL,
  sensor_id      VARCHAR(64) DEFAULT NULL,
  normalized_mac VARCHAR(17) DEFAULT NULL,
  normalized_ssid VARCHAR(256) DEFAULT NULL,
  is_threat      boolean NOT NULL DEFAULT false,
  observed_at    timestamptz NOT NULL,
  projection_run_id uuid DEFAULT NULL,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (node_id)
);

CREATE INDEX IF NOT EXISTS graph_nodes_kind_observed_idx ON atheros_search.graph_nodes (node_kind, observed_at);
CREATE INDEX IF NOT EXISTS graph_nodes_mac_idx ON atheros_search.graph_nodes (normalized_mac);
CREATE INDEX IF NOT EXISTS graph_nodes_ssid_idx ON atheros_search.graph_nodes (normalized_ssid);
CREATE INDEX IF NOT EXISTS graph_nodes_threat_idx ON atheros_search.graph_nodes (is_threat, observed_at);

CREATE TABLE IF NOT EXISTS atheros_search.graph_edges (
  edge_id        VARCHAR(255) NOT NULL,
  source_node_id VARCHAR(255) NOT NULL,
  target_node_id VARCHAR(255) NOT NULL,
  edge_kind      VARCHAR(64) NOT NULL,
  weight         double precision NOT NULL DEFAULT 1,
  label          VARCHAR(255) DEFAULT NULL,
  evidence       jsonb DEFAULT NULL,
  observed_at    timestamptz DEFAULT NULL,
  projection_run_id uuid DEFAULT NULL,
  updated_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (edge_id),
  CONSTRAINT graph_edges_identity_uq UNIQUE (source_node_id, target_node_id, edge_kind)
);

CREATE INDEX IF NOT EXISTS graph_edges_target_idx ON atheros_search.graph_edges (target_node_id, edge_kind);
CREATE INDEX IF NOT EXISTS graph_edges_observed_idx ON atheros_search.graph_edges (observed_at);

CREATE TABLE IF NOT EXISTS atheros_search.inventory_devices (
  mac                   VARCHAR(17) NOT NULL,
  display_name          VARCHAR(255) DEFAULT NULL,
  owner_id              VARCHAR(255) DEFAULT NULL,
  location_id           VARCHAR(128) DEFAULT NULL,
  first_registered      timestamptz DEFAULT NULL,
  last_seen             timestamptz NOT NULL,
  active                boolean NOT NULL DEFAULT true,
  registered            boolean NOT NULL DEFAULT false,
  tags                  jsonb NOT NULL,
  similarity_cluster_id uuid DEFAULT NULL,
  dedup_confidence      double precision DEFAULT NULL,
  known_macs            jsonb NOT NULL,
  projection_run_id     uuid DEFAULT NULL,
  updated_at            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (mac),
  CONSTRAINT inventory_devices_confidence_ck CHECK (
    dedup_confidence IS NULL OR (dedup_confidence >= 0 AND dedup_confidence <= 1)
  )
);

CREATE INDEX IF NOT EXISTS inventory_devices_seen_idx ON atheros_search.inventory_devices (last_seen);
CREATE INDEX IF NOT EXISTS inventory_devices_location_idx ON atheros_search.inventory_devices (location_id, last_seen);
CREATE INDEX IF NOT EXISTS inventory_devices_cluster_idx ON atheros_search.inventory_devices (similarity_cluster_id);

CREATE TABLE IF NOT EXISTS atheros_search.identity_clusters (
  cluster_id            uuid NOT NULL,
  cluster_name          VARCHAR(255) DEFAULT NULL,
  cluster_size          INT NOT NULL DEFAULT 1,
  centroid_document_id  uuid DEFAULT NULL,
  centroid_sample_count INT NOT NULL DEFAULT 0,
  centroid_updated_at   timestamptz DEFAULT NULL,
  first_seen            timestamptz NOT NULL,
  last_seen             timestamptz NOT NULL,
  status                VARCHAR(32) NOT NULL DEFAULT 'active',
  projection_run_id     uuid DEFAULT NULL,
  created_at            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (cluster_id),
  CONSTRAINT identity_clusters_size_ck CHECK (cluster_size > 0)
);

CREATE INDEX IF NOT EXISTS identity_clusters_seen_idx ON atheros_search.identity_clusters (last_seen);

CREATE TABLE IF NOT EXISTS atheros_search.identity_cluster_members (
  cluster_id uuid NOT NULL,
  mac        VARCHAR(17) NOT NULL,
  confidence double precision NOT NULL DEFAULT 1,
  evidence   jsonb NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (cluster_id, mac),
  CONSTRAINT identity_cluster_members_mac_uq UNIQUE (mac),
  CONSTRAINT identity_cluster_members_confidence_ck CHECK (
    confidence >= 0 AND confidence <= 1
  )
);

CREATE TABLE IF NOT EXISTS atheros_search.merge_candidates (
  candidate_id     uuid NOT NULL,
  mac_a            VARCHAR(17) NOT NULL,
  mac_b            VARCHAR(17) NOT NULL,
  confidence       double precision NOT NULL,
  computed_at      timestamptz NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  evidence         jsonb DEFAULT NULL,
  expires_at       timestamptz DEFAULT NULL,
  projection_run_id uuid DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (candidate_id),
  CONSTRAINT merge_candidates_pair_uq UNIQUE (mac_a, mac_b),
  CONSTRAINT merge_candidates_confidence_ck CHECK (
    confidence >= 0 AND confidence <= 1
  ),
  CONSTRAINT merge_candidates_status_ck CHECK (
    status IN ('pending', 'accepted', 'rejected', 'expired')
  )
);

CREATE INDEX IF NOT EXISTS merge_candidates_status_idx ON atheros_search.merge_candidates (status, confidence);

CREATE TABLE IF NOT EXISTS atheros_search.merge_decisions (
  decision_id       uuid NOT NULL,
  candidate_id      uuid NOT NULL,
  decision          VARCHAR(32) NOT NULL,
  decided_at        timestamptz NOT NULL,
  decided_by        VARCHAR(128) DEFAULT NULL,
  reason            TEXT DEFAULT NULL,
  result_cluster_id uuid DEFAULT NULL,
  evidence          jsonb DEFAULT NULL,
  created_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (decision_id),
  CONSTRAINT merge_decisions_candidate_uq UNIQUE (candidate_id),
  CONSTRAINT merge_decisions_decision_ck CHECK (
    decision IN ('merge', 'not_match', 'needs_more_data', 'undo_merge')
  )
);
