-- object: atheros_search_identity_graph
-- depends_on: atheros_search_projection_state
-- Identity-graph tables consumed and maintained by the Octopus coordinator.

CREATE TABLE IF NOT EXISTS atheros_search.merge_candidates (
  candidate_id     text NOT NULL,
  mac_a            VARCHAR(17) NOT NULL,
  mac_b            VARCHAR(17) NOT NULL,
  confidence       double precision NOT NULL DEFAULT 0,
  computed_at      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  evidence         jsonb NOT NULL DEFAULT '{}'::jsonb,
  expires_at       timestamptz DEFAULT NULL,
  projection_run_id text NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (candidate_id),
  CONSTRAINT merge_candidates_mac_uq UNIQUE (mac_a, mac_b)
);

CREATE INDEX IF NOT EXISTS merge_candidates_status_idx ON atheros_search.merge_candidates (status, computed_at);

CREATE TABLE IF NOT EXISTS atheros_search.merge_decisions (
  candidate_id     text NOT NULL,
  decision         VARCHAR(32) NOT NULL,
  decided_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (candidate_id),
  CONSTRAINT merge_decisions_fk FOREIGN KEY (candidate_id)
    REFERENCES atheros_search.merge_candidates (candidate_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS atheros_search.identity_clusters (
  cluster_id       text NOT NULL,
  cluster_name     VARCHAR(255) DEFAULT NULL,
  cluster_size     INT NOT NULL DEFAULT 0,
  first_seen       timestamptz DEFAULT NULL,
  last_seen        timestamptz DEFAULT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'active',
  projection_run_id text NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (cluster_id)
);

CREATE INDEX IF NOT EXISTS identity_clusters_status_idx ON atheros_search.identity_clusters (status, last_seen);

CREATE TABLE IF NOT EXISTS atheros_search.identity_cluster_members (
  cluster_id       text NOT NULL,
  mac              VARCHAR(17) NOT NULL,
  confidence       double precision NOT NULL DEFAULT 0,
  evidence         jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen       timestamptz DEFAULT NULL,
  last_seen        timestamptz DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (mac)
);

CREATE INDEX IF NOT EXISTS identity_cluster_members_cluster_idx ON atheros_search.identity_cluster_members (cluster_id);

CREATE TABLE IF NOT EXISTS atheros_search.graph_nodes (
  node_id          text NOT NULL,
  node_kind        VARCHAR(64) NOT NULL,
  label            TEXT DEFAULT NULL,
  node_payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
  location_id      VARCHAR(128) DEFAULT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  normalized_mac   VARCHAR(17) DEFAULT NULL,
  normalized_ssid  VARCHAR(256) DEFAULT NULL,
  is_threat        boolean NOT NULL DEFAULT false,
  observed_at      timestamptz DEFAULT NULL,
  projection_run_id text NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (node_id)
);

CREATE INDEX IF NOT EXISTS graph_nodes_kind_idx ON atheros_search.graph_nodes (node_kind, observed_at);

CREATE TABLE IF NOT EXISTS atheros_search.graph_edges (
  edge_id          text NOT NULL,
  source_node_id   text NOT NULL,
  target_node_id   text NOT NULL,
  edge_kind        VARCHAR(64) NOT NULL,
  weight           double precision NOT NULL DEFAULT 0,
  label            TEXT DEFAULT NULL,
  evidence         jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at      timestamptz DEFAULT NULL,
  projection_run_id text NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (edge_id)
);

CREATE INDEX IF NOT EXISTS graph_edges_source_idx ON atheros_search.graph_edges (source_node_id, edge_kind);
CREATE INDEX IF NOT EXISTS graph_edges_target_idx ON atheros_search.graph_edges (target_node_id, edge_kind);
