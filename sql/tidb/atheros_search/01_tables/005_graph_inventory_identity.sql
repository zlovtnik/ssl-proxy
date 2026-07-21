-- object: atheros_search_graph_inventory_identity
-- depends_on: atheros_search_projection_state

USE atheros_search;

CREATE TABLE IF NOT EXISTS graph_nodes (
  node_id        VARCHAR(255) NOT NULL,
  node_kind      VARCHAR(32) NOT NULL,
  label          VARCHAR(255) DEFAULT NULL,
  node_payload   JSON NOT NULL,
  location_id    VARCHAR(128) DEFAULT NULL,
  sensor_id      VARCHAR(64) DEFAULT NULL,
  normalized_mac VARCHAR(17) DEFAULT NULL,
  normalized_ssid VARCHAR(256) DEFAULT NULL,
  is_threat      TINYINT(1) NOT NULL DEFAULT 0,
  observed_at    DATETIME(6) NOT NULL,
  projection_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  updated_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (node_id),
  KEY graph_nodes_kind_observed_idx (node_kind, observed_at),
  KEY graph_nodes_mac_idx (normalized_mac),
  KEY graph_nodes_ssid_idx (normalized_ssid),
  KEY graph_nodes_threat_idx (is_threat, observed_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS graph_edges (
  edge_id        VARCHAR(255) NOT NULL,
  source_node_id VARCHAR(255) NOT NULL,
  target_node_id VARCHAR(255) NOT NULL,
  edge_kind      VARCHAR(64) NOT NULL,
  weight         DOUBLE NOT NULL DEFAULT 1,
  label          VARCHAR(255) DEFAULT NULL,
  evidence       JSON DEFAULT NULL,
  observed_at    DATETIME(6) DEFAULT NULL,
  projection_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  updated_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (edge_id),
  UNIQUE KEY graph_edges_identity_uq (source_node_id, target_node_id, edge_kind),
  KEY graph_edges_target_idx (target_node_id, edge_kind),
  KEY graph_edges_observed_idx (observed_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS inventory_devices (
  mac                   VARCHAR(17) NOT NULL,
  display_name          VARCHAR(255) DEFAULT NULL,
  owner_id              VARCHAR(255) DEFAULT NULL,
  location_id           VARCHAR(128) DEFAULT NULL,
  first_registered      DATETIME(6) DEFAULT NULL,
  last_seen             DATETIME(6) NOT NULL,
  active                TINYINT(1) NOT NULL DEFAULT 1,
  registered            TINYINT(1) NOT NULL DEFAULT 0,
  tags                  JSON NOT NULL,
  similarity_cluster_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  dedup_confidence      DOUBLE DEFAULT NULL,
  known_macs            JSON NOT NULL,
  projection_run_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  updated_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (mac),
  KEY inventory_devices_seen_idx (last_seen),
  KEY inventory_devices_location_idx (location_id, last_seen),
  KEY inventory_devices_cluster_idx (similarity_cluster_id),
  CONSTRAINT inventory_devices_confidence_ck CHECK (
    dedup_confidence IS NULL OR (dedup_confidence >= 0 AND dedup_confidence <= 1)
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS identity_clusters (
  cluster_id            CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  cluster_name          VARCHAR(255) DEFAULT NULL,
  cluster_size          INT NOT NULL DEFAULT 1,
  centroid_document_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  centroid_sample_count INT NOT NULL DEFAULT 0,
  centroid_updated_at   DATETIME(6) DEFAULT NULL,
  first_seen            DATETIME(6) NOT NULL,
  last_seen             DATETIME(6) NOT NULL,
  status                VARCHAR(32) NOT NULL DEFAULT 'active',
  projection_run_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  created_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (cluster_id),
  KEY identity_clusters_seen_idx (last_seen),
  CONSTRAINT identity_clusters_size_ck CHECK (cluster_size > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS identity_cluster_members (
  cluster_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  mac        VARCHAR(17) NOT NULL,
  confidence DOUBLE NOT NULL DEFAULT 1,
  evidence   JSON NOT NULL,
  first_seen DATETIME(6) NOT NULL,
  last_seen  DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (cluster_id, mac),
  UNIQUE KEY identity_cluster_members_mac_uq (mac),
  CONSTRAINT identity_cluster_members_confidence_ck CHECK (
    confidence >= 0 AND confidence <= 1
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS merge_candidates (
  candidate_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  mac_a            VARCHAR(17) NOT NULL,
  mac_b            VARCHAR(17) NOT NULL,
  confidence       DOUBLE NOT NULL,
  computed_at      DATETIME(6) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  evidence         JSON DEFAULT NULL,
  expires_at       DATETIME(6) DEFAULT NULL,
  projection_run_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (candidate_id),
  UNIQUE KEY merge_candidates_pair_uq (mac_a, mac_b),
  KEY merge_candidates_status_idx (status, confidence),
  CONSTRAINT merge_candidates_confidence_ck CHECK (
    confidence >= 0 AND confidence <= 1
  ),
  CONSTRAINT merge_candidates_status_ck CHECK (
    status IN ('pending', 'accepted', 'rejected', 'expired')
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS merge_decisions (
  decision_id       CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  candidate_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  decision          VARCHAR(32) NOT NULL,
  decided_at        DATETIME(6) NOT NULL,
  decided_by        VARCHAR(128) DEFAULT NULL,
  reason            TEXT DEFAULT NULL,
  result_cluster_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  evidence          JSON DEFAULT NULL,
  created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (decision_id),
  UNIQUE KEY merge_decisions_candidate_uq (candidate_id),
  CONSTRAINT merge_decisions_decision_ck CHECK (
    decision IN ('merge', 'not_match', 'needs_more_data', 'undo_merge')
  )
) ENGINE=InnoDB;
