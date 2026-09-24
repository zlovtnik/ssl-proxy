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

-- The retired graph_inventory_identity manifest created these relations with
-- UUID identifiers and weaker nullability. Normalize that preserved shape
-- before recording this migration; CREATE TABLE IF NOT EXISTS alone cannot do
-- that work.
DO $$
BEGIN
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.merge_candidates'::regclass
      AND attribute.attname = 'candidate_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.merge_candidates
      ALTER COLUMN candidate_id TYPE text USING candidate_id::text;
  END IF;
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.merge_candidates'::regclass
      AND attribute.attname = 'projection_run_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.merge_candidates
      ALTER COLUMN projection_run_id TYPE text USING projection_run_id::text;
  END IF;
END $$;
ALTER TABLE atheros_search.merge_candidates
  ALTER COLUMN confidence SET DEFAULT 0,
  ALTER COLUMN computed_at SET DEFAULT CURRENT_TIMESTAMP,
  ALTER COLUMN evidence SET DEFAULT '{}'::jsonb;
UPDATE atheros_search.merge_candidates
SET evidence = COALESCE(evidence, '{}'::jsonb),
    projection_run_id = COALESCE(projection_run_id, candidate_id)
WHERE evidence IS NULL OR projection_run_id IS NULL;
ALTER TABLE atheros_search.merge_candidates
  ALTER COLUMN evidence SET DEFAULT '{}'::jsonb,
  ALTER COLUMN evidence SET NOT NULL,
  ALTER COLUMN projection_run_id SET NOT NULL;

DROP INDEX IF EXISTS atheros_search.merge_candidates_status_idx;
CREATE INDEX merge_candidates_status_idx ON atheros_search.merge_candidates (status, computed_at);

CREATE TABLE IF NOT EXISTS atheros_search.merge_decisions (
  candidate_id     text NOT NULL,
  decision         VARCHAR(32) NOT NULL,
  decided_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (candidate_id),
  CONSTRAINT merge_decisions_fk FOREIGN KEY (candidate_id)
    REFERENCES atheros_search.merge_candidates (candidate_id) ON DELETE CASCADE
);

DO $$
BEGIN
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.merge_decisions'::regclass
      AND attribute.attname = 'candidate_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.merge_decisions
      ALTER COLUMN candidate_id TYPE text USING candidate_id::text;
  END IF;
END $$;

ALTER TABLE atheros_search.merge_decisions
  ALTER COLUMN decided_at SET DEFAULT CURRENT_TIMESTAMP,
  DROP COLUMN IF EXISTS decision_id;

DELETE FROM atheros_search.merge_decisions decision
WHERE NOT EXISTS (
  SELECT 1
  FROM atheros_search.merge_candidates candidate
  WHERE candidate.candidate_id = decision.candidate_id
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'atheros_search.merge_decisions'::regclass
      AND contype = 'p'
  ) THEN
    ALTER TABLE atheros_search.merge_decisions
      ADD CONSTRAINT merge_decisions_pkey PRIMARY KEY (candidate_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'atheros_search.merge_decisions'::regclass
      AND conname = 'merge_decisions_fk'
  ) THEN
    ALTER TABLE atheros_search.merge_decisions
      ADD CONSTRAINT merge_decisions_fk FOREIGN KEY (candidate_id)
      REFERENCES atheros_search.merge_candidates (candidate_id) ON DELETE CASCADE;
  END IF;
END $$;

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

DO $$
BEGIN
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.identity_clusters'::regclass
      AND attribute.attname = 'cluster_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.identity_clusters
      ALTER COLUMN cluster_id TYPE text USING cluster_id::text;
  END IF;
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.identity_clusters'::regclass
      AND attribute.attname = 'projection_run_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.identity_clusters
      ALTER COLUMN projection_run_id TYPE text USING projection_run_id::text;
  END IF;
END $$;
ALTER TABLE atheros_search.identity_clusters
  ALTER COLUMN cluster_size SET DEFAULT 0;
UPDATE atheros_search.identity_clusters
SET projection_run_id = COALESCE(projection_run_id, cluster_id)
WHERE projection_run_id IS NULL;
ALTER TABLE atheros_search.identity_clusters
  ALTER COLUMN first_seen DROP NOT NULL,
  ALTER COLUMN last_seen DROP NOT NULL,
  ALTER COLUMN projection_run_id SET NOT NULL;

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

DO $$
BEGIN
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.identity_cluster_members'::regclass
      AND attribute.attname = 'cluster_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.identity_cluster_members
      ALTER COLUMN cluster_id TYPE text USING cluster_id::text;
  END IF;
END $$;
ALTER TABLE atheros_search.identity_cluster_members
  ALTER COLUMN confidence SET DEFAULT 0,
  ALTER COLUMN evidence SET DEFAULT '{}'::jsonb;
UPDATE atheros_search.identity_cluster_members
SET evidence = COALESCE(evidence, '{}'::jsonb)
WHERE evidence IS NULL;
ALTER TABLE atheros_search.identity_cluster_members
  ALTER COLUMN evidence SET NOT NULL,
  ALTER COLUMN first_seen DROP NOT NULL,
  ALTER COLUMN last_seen DROP NOT NULL;

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

ALTER TABLE atheros_search.graph_nodes
  ADD COLUMN IF NOT EXISTS label TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS location_id VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS normalized_mac VARCHAR(17) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS normalized_ssid VARCHAR(256) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS is_threat boolean NOT NULL DEFAULT false;

DO $$
BEGIN
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.graph_nodes'::regclass
      AND attribute.attname = 'node_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.graph_nodes
      ALTER COLUMN node_id TYPE text USING node_id::text;
  END IF;
  IF (
    SELECT attribute.atttypid <> 'text'::regtype
    FROM pg_attribute attribute
    WHERE attribute.attrelid = 'atheros_search.graph_nodes'::regclass
      AND attribute.attname = 'projection_run_id'
      AND NOT attribute.attisdropped
  ) THEN
    ALTER TABLE atheros_search.graph_nodes
      ALTER COLUMN projection_run_id TYPE text USING projection_run_id::text;
  END IF;
END $$;
ALTER TABLE atheros_search.graph_nodes
  ALTER COLUMN node_kind TYPE VARCHAR(64) USING node_kind::VARCHAR(64),
  ALTER COLUMN node_payload SET DEFAULT '{}'::jsonb,
  ALTER COLUMN observed_at DROP NOT NULL;
UPDATE atheros_search.graph_nodes
SET node_payload = COALESCE(node_payload, '{}'::jsonb),
    projection_run_id = COALESCE(projection_run_id, node_id)
WHERE node_payload IS NULL OR projection_run_id IS NULL;
ALTER TABLE atheros_search.graph_nodes
  ALTER COLUMN node_payload SET NOT NULL,
  ALTER COLUMN projection_run_id SET NOT NULL;

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

ALTER TABLE atheros_search.graph_edges
  ADD COLUMN IF NOT EXISTS label TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS observed_at timestamptz DEFAULT NULL;

DO $$
DECLARE
  column_name text;
BEGIN
  FOREACH column_name IN ARRAY ARRAY['edge_id', 'source_node_id', 'target_node_id', 'projection_run_id']
  LOOP
    IF (
      SELECT attribute.atttypid <> 'text'::regtype
      FROM pg_attribute attribute
      WHERE attribute.attrelid = 'atheros_search.graph_edges'::regclass
        AND attribute.attname = column_name
        AND NOT attribute.attisdropped
    ) THEN
      EXECUTE format(
        'ALTER TABLE atheros_search.graph_edges ALTER COLUMN %I TYPE text USING %I::text',
        column_name,
        column_name
      );
    END IF;
  END LOOP;
END $$;
ALTER TABLE atheros_search.graph_edges
  ALTER COLUMN weight SET DEFAULT 0,
  ALTER COLUMN evidence SET DEFAULT '{}'::jsonb;
UPDATE atheros_search.graph_edges
SET evidence = COALESCE(evidence, '{}'::jsonb),
    projection_run_id = COALESCE(projection_run_id, edge_id)
WHERE evidence IS NULL OR projection_run_id IS NULL;
ALTER TABLE atheros_search.graph_edges
  ALTER COLUMN evidence SET NOT NULL,
  ALTER COLUMN projection_run_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS graph_edges_source_idx ON atheros_search.graph_edges (source_node_id, edge_kind);
CREATE INDEX IF NOT EXISTS graph_edges_target_idx ON atheros_search.graph_edges (target_node_id, edge_kind);
