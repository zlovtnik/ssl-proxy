-- Edge provenance for the identity graph. Edges carried a numeric weight with
-- no documented basis; this file gives every edge an honest explanation of
-- what its weight measures so the console can render "why are these linked".
-- Append-only: the graph tables themselves stay owned by 011_identity_graph.

ALTER TABLE atheros_search.graph_edges
  ADD COLUMN IF NOT EXISTS weight_basis VARCHAR(64) NOT NULL DEFAULT 'unspecified';

-- Documented weight_basis vocabulary. Enforced by convention in the Octopus
-- projector (IdentityGraphSql); the Go reader passes the value through.
--   frame_count          - weight counts wireless frames observed
--   cluster_confidence   - weight is the identity-cluster membership confidence
--   vendor_match         - weight counts OUI/vendor attributes in common
--   time_overlap_windows - weight counts overlapping sensor-time windows
--   probe_overlap        - weight counts shared probed SSIDs
--   channel_overlap      - weight counts shared channel observations
--   unspecified          - legacy rows written before this column existed

UPDATE atheros_search.graph_edges
   SET weight_basis = 'frame_count'
 WHERE edge_kind = 'observed_at'
   AND weight_basis = 'unspecified';

UPDATE atheros_search.graph_edges
   SET weight_basis = 'cluster_confidence'
 WHERE edge_kind = 'identity_member'
   AND weight_basis = 'unspecified';