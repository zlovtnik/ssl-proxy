package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckRogueRFPaths(ctx context.Context, pool *pgxpool.Pool, cfg Config) (int, error) {
	tag, err := pool.Exec(ctx, `
WITH RECURSIVE seed AS (
  SELECT bssid AS root_bssid, composite_risk
  FROM mv_ap_risk_score
  WHERE composite_risk > $1
),
walk AS (
  SELECT
    root_bssid,
    composite_risk,
    root_bssid AS node,
    'bssid'::text AS node_type,
    ARRAY[root_bssid] AS path,
    0 AS depth
  FROM seed
  UNION ALL
  SELECT
    walk.root_bssid,
    walk.composite_risk,
    edge.next_node,
    edge.next_node_type,
    walk.path || edge.next_node,
    walk.depth + 1
  FROM walk
  JOIN LATERAL (
    SELECT node_b AS next_node, node_b_type AS next_node_type, edge_type
    FROM vec_infrastructure_graph
    WHERE node_a = walk.node
      AND node_a_type = walk.node_type
      AND last_seen >= now() - interval '24 hours'
    UNION ALL
    SELECT node_a AS next_node, node_a_type AS next_node_type, edge_type
    FROM vec_infrastructure_graph
    WHERE node_b = walk.node
      AND node_b_type = walk.node_type
      AND last_seen >= now() - interval '24 hours'
  ) edge ON true
  WHERE walk.depth < $2
    AND edge.edge_type IN ('association', 'roaming', 'rf_proximity')
    AND NOT edge.next_node = ANY(walk.path)
),
candidates AS (
  SELECT DISTINCT ON (root_bssid, node, node_type)
    root_bssid,
    composite_risk,
    node,
    node_type,
    path,
    depth
  FROM walk
  WHERE depth > 0
    AND node_type IN ('client_mac', 'bssid')
  ORDER BY root_bssid, node, node_type, depth ASC
  LIMIT 200
)
INSERT INTO vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
SELECT
  'rogue_rf_path',
  CASE WHEN node_type = 'client_mac' THEN node ELSE root_bssid END,
  composite_risk,
  concat('Rogue RF path from high-risk AP ', root_bssid, ' to ', node_type, ' ', node, ' depth=', depth),
  jsonb_build_object(
    'root_bssid', root_bssid,
    'target_node', node,
    'target_node_type', node_type,
    'path', path,
    'depth', depth,
    'max_depth', $2,
    'composite_risk', composite_risk,
    'ap_risk_threshold', $1
  )
FROM candidates
WHERE NOT EXISTS (
  SELECT 1 FROM vec_alerts a
  WHERE a.alert_type = 'rogue_rf_path'
    AND a.source_mac IS NOT DISTINCT FROM CASE WHEN candidates.node_type = 'client_mac' THEN candidates.node ELSE candidates.root_bssid END
    AND a.metadata->>'root_bssid' = candidates.root_bssid
    AND a.metadata->>'target_node' = candidates.node
    AND a.created_at > now() - interval '1 hour'
)
`, cfg.APRiskThreshold, cfg.GraphMaxDepth)
	if err != nil {
		return 0, fmt.Errorf("rogue_rf_path query failed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
