package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AlertResult struct {
	ID              int64
	AlertType       string
	SourceMAC       string
	Score           float64
	ExplanationText string
	MetadataJSON    string
}

type CorrelationResult struct {
	LeftSourceKey    string
	RightSourceKey   string
	LeftSensorID     string
	RightSensorID    string
	CosineSimilarity float64
}

type RotationCluster struct {
	SourceMAC        string
	RelatedMAC       string
	CosineSimilarity float64
	Reason           string
}

type GraphEdge struct {
	NodeA     string
	NodeAType string
	NodeB     string
	NodeBType string
	EdgeType  string
	Weight    float64
}

func SearchAlerts(ctx context.Context, pool *pgxpool.Pool, limit int) ([]AlertResult, error) {
	rows, err := pool.Query(ctx, `
SELECT id, alert_type, coalesce(source_mac, ''), coalesce(score, 0), coalesce(explanation_text, ''), coalesce(metadata, '{}'::jsonb)::text
FROM vec_alerts
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertResult
	for rows.Next() {
		var item AlertResult
		if err := rows.Scan(&item.ID, &item.AlertType, &item.SourceMAC, &item.Score, &item.ExplanationText, &item.MetadataJSON); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func CrossSensorCorrelation(ctx context.Context, pool *pgxpool.Pool, sourceKey string, limit int) ([]CorrelationResult, error) {
	rows, err := pool.Query(ctx, `
SELECT left_source_key, right_source_key, coalesce(left_sensor_id, ''), coalesce(right_sensor_id, ''), cosine_similarity
FROM vec_similarity_pairs_expanded
WHERE pair_kind = 'cross_sensor'
  AND (left_source_key = $1 OR right_source_key = $1)
ORDER BY cosine_similarity DESC
LIMIT $2`, sourceKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CorrelationResult
	for rows.Next() {
		var item CorrelationResult
		if err := rows.Scan(&item.LeftSourceKey, &item.RightSourceKey, &item.LeftSensorID, &item.RightSensorID, &item.CosineSimilarity); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func FindRotations(ctx context.Context, pool *pgxpool.Pool, sourceMAC string, windowHours int) ([]RotationCluster, error) {
	rows, err := pool.Query(ctx, `
SELECT
  coalesce(p.left_source_mac, ''),
  coalesce(p.right_source_mac, ''),
  p.cosine_similarity,
  coalesce(alert.reason, '')
FROM vec_similarity_pairs_expanded p
JOIN wireless_shadow_alerts alert
  ON alert.reason = 'mac_rotation_suspected'
 AND alert.resolved_at IS NULL
 AND lower(alert.source_mac) IN (lower(coalesce(p.left_source_mac, '')), lower(coalesce(p.right_source_mac, '')))
WHERE p.pair_kind = 'device_device'
  AND p.computed_at >= now() - make_interval(hours => $2)
  AND ($1 = '' OR lower($1) IN (lower(coalesce(p.left_source_mac, '')), lower(coalesce(p.right_source_mac, ''))))
ORDER BY p.cosine_similarity DESC
LIMIT 100`, sourceMAC, windowHours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RotationCluster
	for rows.Next() {
		var item RotationCluster
		if err := rows.Scan(&item.SourceMAC, &item.RelatedMAC, &item.CosineSimilarity, &item.Reason); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func InfrastructureNeighborhood(ctx context.Context, pool *pgxpool.Pool, node string, edgeTypes []string, limit int) ([]GraphEdge, error) {
	rows, err := pool.Query(ctx, `
SELECT node_a, node_a_type, node_b, node_b_type, edge_type, weight::double precision
FROM vec_infrastructure_graph
WHERE (node_a = $1 OR node_b = $1)
  AND (cardinality($2::text[]) = 0 OR edge_type = any($2::text[]))
ORDER BY last_seen DESC, weight DESC
LIMIT $3`, node, edgeTypes, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GraphEdge
	for rows.Next() {
		var item GraphEdge
		if err := rows.Scan(&item.NodeA, &item.NodeAType, &item.NodeB, &item.NodeBType, &item.EdgeType, &item.Weight); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
