-- Durable confirmation provenance for identity candidates. Automatic
-- confirmations require both the hard similarity threshold and a trusted,
-- nonempty registered identity shared by both device records.
ALTER TABLE atheros_search.merge_candidates
  ADD COLUMN IF NOT EXISTS confirmation_source VARCHAR(16) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS trusted_registered_device_id uuid DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS confirmed_at timestamptz DEFAULT NULL;

ALTER TABLE atheros_search.merge_candidates
  DROP CONSTRAINT IF EXISTS merge_candidates_confirmation_source_ck,
  ADD CONSTRAINT merge_candidates_confirmation_source_ck CHECK (
    confirmation_source IS NULL OR confirmation_source IN ('human', 'automatic')
  ),
  DROP CONSTRAINT IF EXISTS merge_candidates_automatic_confirmation_ck,
  ADD CONSTRAINT merge_candidates_automatic_confirmation_ck CHECK (
    confirmation_source <> 'automatic'
    OR (
      confidence >= 0.98
      AND trusted_registered_device_id IS NOT NULL
      AND confirmed_at IS NOT NULL
    )
  );

CREATE INDEX IF NOT EXISTS merge_candidates_confirmation_idx
  ON atheros_search.merge_candidates (status, confirmation_source, confirmed_at);

CREATE INDEX IF NOT EXISTS graph_edges_same_device_idx
  ON atheros_search.graph_edges (edge_kind, source_node_id, target_node_id)
  WHERE edge_kind = 'same_device';

-- same_device graph edges use weight_basis = 'cosine_similarity'; their
-- numeric weight is the candidate's persisted device-device similarity.
