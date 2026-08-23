package search

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	graphDefaultLimit = 200
	graphMaxLimit     = 500
	graphCacheTTL     = 10 * time.Second
)

type NodeKind string

const (
	NodeKindDevice      NodeKind = "device"
	NodeKindCluster     NodeKind = "cluster"
	NodeKindAP          NodeKind = "ap"
	NodeKindClient      NodeKind = "client"
	NodeKindShadowAlert NodeKind = "shadow_alert"
	NodeKindAlert       NodeKind = "alert"
	NodeKindEmbedding   NodeKind = "embedding"
)

type EdgeKind string

const (
	EdgeKindAssociation   EdgeKind = "association"
	EdgeKindProbe         EdgeKind = "probe"
	EdgeKindClusterMember EdgeKind = "cluster_member"
	EdgeKindShadow        EdgeKind = "shadow"
	EdgeKindAlertRef      EdgeKind = "alert_ref"
	EdgeKindRFProximity   EdgeKind = "rf_proximity"
	EdgeKindRoaming       EdgeKind = "roaming"
	EdgeKindSameChannel   EdgeKind = "same_channel"
	EdgeKindVendorLink    EdgeKind = "vendor_link"
)

type GraphNode struct {
	ID                  string     `json:"id"`
	Kind                NodeKind   `json:"kind"`
	Label               string     `json:"label"`
	MAC                 string     `json:"mac,omitempty"`
	DisplayName         string     `json:"display_name,omitempty"`
	Username            string     `json:"username,omitempty"`
	Hostname            string     `json:"hostname,omitempty"`
	OSHint              string     `json:"os_hint,omitempty"`
	SSID                string     `json:"ssid,omitempty"`
	BSSID               string     `json:"bssid,omitempty"`
	LocationID          string     `json:"location_id,omitempty"`
	SensorID            string     `json:"sensor_id,omitempty"`
	Enabled             *bool      `json:"enabled,omitempty"`
	SignalDBM           *int32     `json:"signal_dbm,omitempty"`
	RiskScore           *float64   `json:"risk_score,omitempty"`
	Score               *float64   `json:"score,omitempty"`
	Tags                []string   `json:"tags,omitempty"`
	ClusterSize         *int32     `json:"cluster_size,omitempty"`
	AlertType           string     `json:"alert_type,omitempty"`
	Reason              string     `json:"reason,omitempty"`
	OccurrenceCount     *int64     `json:"occurrence_count,omitempty"`
	ProbeCount          *int64     `json:"probe_count,omitempty"`
	CentroidUpdatedAt   *time.Time `json:"centroid_updated_at,omitempty"`
	CentroidSampleCount *int32     `json:"centroid_sample_count,omitempty"`
	CreatedAt           *time.Time `json:"created_at,omitempty"`
	FirstSeen           *time.Time `json:"first_seen,omitempty"`
	LastSeen            *time.Time `json:"last_seen,omitempty"`
	ResolvedAt          *time.Time `json:"resolved_at,omitempty"`
	EventSourceMACs     []string   `json:"event_source_macs,omitempty"`
	EventSSIDs          []string   `json:"event_ssids,omitempty"`
	ExplainSourceKey    string     `json:"explain_source_key,omitempty"`
	ExplainKind         string     `json:"explain_kind,omitempty"`
}

type GraphResponseEdge struct {
	ID     string   `json:"id"`
	Source string   `json:"source"`
	Target string   `json:"target"`
	Kind   EdgeKind `json:"kind"`
	Weight *float64 `json:"weight,omitempty"`
	Label  string   `json:"label,omitempty"`
}

type GraphResponse struct {
	Nodes       []GraphNode         `json:"nodes"`
	Edges       []GraphResponseEdge `json:"edges"`
	GeneratedAt time.Time           `json:"generated_at"`
	NodeCount   int                 `json:"node_count"`
	EdgeCount   int                 `json:"edge_count"`
}

type GraphFilters struct {
	LocationIDs    []string   `json:"location_ids,omitempty"`
	SensorIDs      []string   `json:"sensor_ids,omitempty"`
	SourceMAC      string     `json:"source_mac,omitempty"`
	SSID           string     `json:"ssid,omitempty"`
	Kinds          []NodeKind `json:"kinds,omitempty"`
	ThreatOnly     bool       `json:"threat_only,omitempty"`
	ObservedAfter  *time.Time `json:"observed_after,omitempty"`
	ObservedBefore *time.Time `json:"observed_before,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

type graphCacheEntry struct {
	expiresAt time.Time
	response  *GraphResponse
}

func (s *Service) Graph(ctx context.Context, filters GraphFilters) (*GraphResponse, error) {
	if err := ValidateGraphFilters(filters); err != nil {
		return nil, err
	}
	filters = normalizeGraphFilters(filters)
	cacheKey, err := graphFilterKey(filters)
	if err != nil {
		return nil, err
	}
	if cached, ok := s.graphCache.Load(cacheKey); ok {
		entry := cached.(graphCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.response, nil
		}
		s.graphCache.Delete(cacheKey)
	}

	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodes, err := fetchGraphNodes(ctx, tx, filters)
	if err != nil {
		return nil, err
	}
	edges, err := fetchGraphEdges(ctx, tx, nodes)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	response := &GraphResponse{
		Nodes:       nodes,
		Edges:       edges,
		GeneratedAt: time.Now().UTC(),
		NodeCount:   len(nodes),
		EdgeCount:   len(edges),
	}
	s.graphCache.Store(cacheKey, graphCacheEntry{expiresAt: time.Now().Add(graphCacheTTL), response: response})
	return response, nil
}

func fetchGraphNodes(ctx context.Context, tx *sql.Tx, filters GraphFilters) ([]GraphNode, error) {
	query, args := graphNodesQuery(filters)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make([]GraphNode, 0, filters.Limit)
	for rows.Next() {
		var id, kind, label, payload string
		if err := rows.Scan(&id, &kind, &label, &payload); err != nil {
			return nil, err
		}
		node := GraphNode{ID: id, Kind: NodeKind(kind), Label: label}
		if strings.TrimSpace(payload) != "" && payload != "null" {
			if err := json.Unmarshal([]byte(payload), &node); err != nil {
				return nil, fmt.Errorf("decode graph node %q: %w", id, err)
			}
		}
		node.ID, node.Kind, node.Label = id, NodeKind(kind), label
		nodes = append(nodes, node)
		if len(nodes) >= filters.Limit {
			break
		}
	}
	return nodes, rows.Err()
}

func graphNodesQuery(filters GraphFilters) (string, []any) {
	clauses := []string{"1 = 1"}
	args := make([]any, 0)
	addInClause(&clauses, &args, "location_id", stringsToAny(filters.LocationIDs))
	addInClause(&clauses, &args, "sensor_id", stringsToAny(filters.SensorIDs))
	if filters.SourceMAC != "" {
		clauses = append(clauses, fmt.Sprintf("normalized_mac = $%d", len(args)+1))
		args = append(args, filters.SourceMAC)
	}
	if filters.SSID != "" {
		clauses = append(clauses, fmt.Sprintf("normalized_ssid LIKE $%d ESCAPE E'\\\\'", len(args)+1))
		args = append(args, "%"+escapeLike(strings.ToLower(filters.SSID))+"%")
	}
	if len(filters.Kinds) > 0 {
		values := make([]any, 0, len(filters.Kinds))
		for _, kind := range filters.Kinds {
			values = append(values, string(kind))
		}
		addInClause(&clauses, &args, "node_kind", values)
	}
	if filters.ThreatOnly {
		clauses = append(clauses, "is_threat")
	}
	if filters.ObservedAfter != nil {
		clauses = append(clauses, fmt.Sprintf("observed_at >= $%d", len(args)+1))
		args = append(args, filters.ObservedAfter.UTC())
	}
	if filters.ObservedBefore != nil {
		clauses = append(clauses, fmt.Sprintf("observed_at <= $%d", len(args)+1))
		args = append(args, filters.ObservedBefore.UTC())
	}
	args = append(args, filters.Limit)
	return `
SELECT node_id, node_kind, COALESCE(label, node_id), node_payload::text
FROM atheros_search.graph_nodes
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY observed_at DESC, node_id ASC
LIMIT $` + fmt.Sprint(len(args)), args
}

func fetchGraphEdges(ctx context.Context, tx *sql.Tx, nodes []GraphNode) ([]GraphResponseEdge, error) {
	if len(nodes) == 0 {
		return []GraphResponseEdge{}, nil
	}
	firstPlaceholders := pgPlaceholders(1, len(nodes))
	secondPlaceholders := pgPlaceholders(len(nodes)+1, len(nodes))
	args := make([]any, 0, len(nodes)*2)
	for _, node := range nodes {
		args = append(args, node.ID)
	}
	for _, node := range nodes {
		args = append(args, node.ID)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT edge_id, source_node_id, target_node_id, edge_kind, weight, COALESCE(label, '')
FROM atheros_search.graph_edges
WHERE source_node_id IN (`+firstPlaceholders+`)
  AND target_node_id IN (`+secondPlaceholders+`)
ORDER BY edge_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	edges := make([]GraphResponseEdge, 0)
	for rows.Next() {
		var edge GraphResponseEdge
		var kind string
		var weight sql.NullFloat64
		if err := rows.Scan(&edge.ID, &edge.Source, &edge.Target, &kind, &weight, &edge.Label); err != nil {
			return nil, err
		}
		edge.Kind = EdgeKind(kind)
		if weight.Valid {
			edge.Weight = &weight.Float64
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func addInClause(clauses *[]string, args *[]any, column string, values []any) {
	if len(values) == 0 {
		return
	}
	*clauses = append(*clauses, column+" IN ("+pgPlaceholders(len(*args)+1, len(values))+")")
	*args = append(*args, values...)
}

func pgPlaceholders(start, count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = fmt.Sprintf("$%d", start+index)
	}
	return strings.Join(values, ",")
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out
}

func normalizeGraphFilters(filters GraphFilters) GraphFilters {
	if filters.Limit <= 0 {
		filters.Limit = graphDefaultLimit
	}
	if filters.Limit > graphMaxLimit {
		filters.Limit = graphMaxLimit
	}
	filters.LocationIDs = normalizeGraphList(filters.LocationIDs)
	filters.SensorIDs = normalizeGraphList(filters.SensorIDs)
	filters.SourceMAC = strings.ToLower(strings.TrimSpace(filters.SourceMAC))
	filters.SSID = strings.TrimSpace(filters.SSID)
	kinds := make([]NodeKind, 0, len(filters.Kinds))
	seen := map[NodeKind]struct{}{}
	for _, kind := range filters.Kinds {
		if _, ok := seen[kind]; ok {
			continue
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	filters.Kinds = kinds
	return filters
}

func normalizeGraphList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func graphFilterKey(filters GraphFilters) (string, error) {
	body, err := json.Marshal(filters)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func validGraphNodeKind(kind NodeKind) bool {
	switch kind {
	case NodeKindDevice, NodeKindCluster, NodeKindAP, NodeKindClient, NodeKindShadowAlert, NodeKindAlert:
		return true
	default:
		return false
	}
}

func ValidateGraphFilters(filters GraphFilters) error {
	for _, kind := range filters.Kinds {
		if !validGraphNodeKind(kind) {
			return fmt.Errorf("unsupported graph node kind %q", kind)
		}
	}
	if filters.ObservedAfter != nil && filters.ObservedBefore != nil && filters.ObservedAfter.After(*filters.ObservedBefore) {
		return errors.New("observed_after must be before observed_before")
	}
	return nil
}
