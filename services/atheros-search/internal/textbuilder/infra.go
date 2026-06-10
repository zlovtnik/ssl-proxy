package textbuilder

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

type InfrastructureGraphRow struct {
	QueryKey  string
	NodeA     string
	NodeAType string
	NodeB     string
	NodeBType string
	EdgeType  string
	Weight    string
	LastSeen  pgtype.Timestamptz
}

func buildInfrastructureSubgraphsBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT DISTINCT ON (
  LEAST(node_a, node_b),
  GREATEST(node_a, node_b),
  edge_type,
  endpoint
)
  endpoint AS query_key,
  node_a,
  node_a_type,
  node_b,
  node_b_type,
  edge_type,
  coalesce(weight::text, ''),
  last_seen
FROM vec_infrastructure_graph
CROSS JOIN LATERAL (
  VALUES
    (CASE WHEN node_a = ANY($1::text[]) THEN node_a END),
    (CASE WHEN node_b = ANY($1::text[]) THEN node_b END)
) AS endpoints(endpoint)
WHERE endpoint IS NOT NULL
ORDER BY
  LEAST(node_a, node_b),
  GREATEST(node_a, node_b),
  edge_type,
  endpoint,
  last_seen DESC
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("infrastructure_subgraph batch query failed: %w", err)
	}
	defer rows.Close()

	grouped := map[string][]InfrastructureGraphRow{}
	for rows.Next() {
		var row InfrastructureGraphRow
		if err := rows.Scan(&row.QueryKey, &row.NodeA, &row.NodeAType, &row.NodeB, &row.NodeBType, &row.EdgeType, &row.Weight, &row.LastSeen); err != nil {
			return fmt.Errorf("scan infrastructure_subgraph row: %w", err)
		}
		grouped[row.QueryKey] = append(grouped[row.QueryKey], row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read infrastructure_subgraph rows: %w", err)
	}
	for key, rows := range grouped {
		out[key] = buildEgoGraphInput(key, rows)
	}
	return nil
}

func buildEgoGraphInput(center string, rows []InfrastructureGraphRow) db.EmbeddingInput {
	lines := []string{"kind: infrastructure_subgraph", "center: " + center}
	clients := map[string]struct{}{}
	ssids := map[string]struct{}{}
	vendors := map[string]struct{}{}
	edgeCounts := map[string]int{}
	var latest pgtype.Timestamptz

	for _, row := range rows {
		neighbor, neighborType := row.NodeB, row.NodeBType
		if row.NodeB == center {
			neighbor, neighborType = row.NodeA, row.NodeAType
		}
		switch {
		case neighborType == "client_mac" && row.EdgeType == "association":
			clients[neighbor] = struct{}{}
		case neighborType == "ssid" && row.EdgeType == "probe_target":
			ssids[neighbor] = struct{}{}
		case neighborType == "vendor":
			vendors[neighbor] = struct{}{}
		}
		edgeCounts[row.EdgeType]++
		if row.LastSeen.Valid && (!latest.Valid || row.LastSeen.Time.After(latest.Time)) {
			latest = row.LastSeen
		}
	}
	if len(ssids) > 0 {
		lines = append(lines, fmt.Sprintf("ssid: %d", len(ssids)))
	}
	if len(clients) > 0 {
		lines = append(lines, fmt.Sprintf("clients: %d", len(clients)))
	}
	if len(vendors) > 0 {
		lines = append(lines, fmt.Sprintf("vendor_diversity: %d", len(vendors)))
	}
	edgeParts := make([]string, 0, len(edgeCounts))
	for edgeType, count := range edgeCounts {
		edgeParts = append(edgeParts, fmt.Sprintf("%s:%d", edgeType, count))
	}
	sort.Strings(edgeParts)
	lines = append(lines, "edges: "+strings.Join(edgeParts, ","))
	return db.EmbeddingInput{
		Text:             clampDefault(strings.Join(lines, "\n")),
		SourceObservedAt: optionalTime(latest.Valid, latest.Time),
		SourceMAC:        center,
	}
}
