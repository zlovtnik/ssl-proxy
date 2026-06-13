package search

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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

type graphBuilder struct {
	nodes map[string]GraphNode
	edges map[string]GraphResponseEdge

	devicesByMAC map[string]string
	apsByBSSID   map[string]string
	apsBySSID    map[string]string
	clientsByMAC map[string]string

	clusterMembers map[string][]string
}

func (s *Service) Graph(ctx context.Context, filters GraphFilters) (*GraphResponse, error) {
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

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	builder := newGraphBuilder()
	kinds := graphKindSet(filters)
	if kinds[NodeKindDevice] {
		if err := fetchGraphDevices(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}
	if kinds[NodeKindCluster] && !filters.ThreatOnly {
		if err := fetchGraphClusters(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}
	if kinds[NodeKindAP] && !filters.ThreatOnly {
		if err := fetchGraphAPs(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}
	if kinds[NodeKindClient] && !filters.ThreatOnly {
		if err := fetchGraphClients(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}
	if kinds[NodeKindShadowAlert] {
		if err := fetchGraphShadowAlerts(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}
	if kinds[NodeKindAlert] {
		if err := fetchGraphAlerts(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}

	builder.prune(filters.Limit)
	builder.rebuildIndexes()
	builder.addLocalEdges()
	if !filters.ThreatOnly {
		if err := fetchGraphInfrastructureEdges(ctx, tx, filters, builder); err != nil {
			return nil, err
		}
	}

	nodes := builder.sortedNodes()
	edges := builder.sortedEdges()
	resp := &GraphResponse{
		Nodes:       nodes,
		Edges:       edges,
		GeneratedAt: time.Now().UTC(),
		NodeCount:   len(nodes),
		EdgeCount:   len(edges),
	}
	s.graphCache.Store(cacheKey, graphCacheEntry{expiresAt: time.Now().Add(graphCacheTTL), response: resp})
	return resp, nil
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
		if !validGraphNodeKind(kind) {
			continue
		}
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
	case NodeKindDevice, NodeKindCluster, NodeKindAP, NodeKindClient, NodeKindShadowAlert, NodeKindAlert, NodeKindEmbedding:
		return true
	default:
		return false
	}
}

func graphKindSet(filters GraphFilters) map[NodeKind]bool {
	out := map[NodeKind]bool{}
	if len(filters.Kinds) == 0 {
		out[NodeKindDevice] = true
		out[NodeKindCluster] = true
		out[NodeKindAP] = true
		out[NodeKindClient] = true
		out[NodeKindShadowAlert] = true
		out[NodeKindAlert] = true
		return out
	}
	for _, kind := range filters.Kinds {
		out[kind] = true
	}
	return out
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		nodes:          map[string]GraphNode{},
		edges:          map[string]GraphResponseEdge{},
		devicesByMAC:   map[string]string{},
		apsByBSSID:     map[string]string{},
		apsBySSID:      map[string]string{},
		clientsByMAC:   map[string]string{},
		clusterMembers: map[string][]string{},
	}
}

func (b *graphBuilder) addNode(node GraphNode) {
	if node.ID == "" {
		return
	}
	b.nodes[node.ID] = node
	b.indexNode(node)
}

func (b *graphBuilder) indexNode(node GraphNode) {
	switch node.Kind {
	case NodeKindDevice:
		if key := graphNorm(node.MAC); key != "" {
			b.devicesByMAC[key] = node.ID
		}
	case NodeKindAP:
		if key := graphNorm(node.BSSID); key != "" {
			b.apsByBSSID[key] = node.ID
		}
		if key := graphNorm(node.SSID); key != "" {
			b.apsBySSID[key] = node.ID
		}
	case NodeKindClient:
		if key := graphNorm(node.MAC); key != "" {
			b.clientsByMAC[key] = node.ID
		}
	}
}

func (b *graphBuilder) addEdge(edge GraphResponseEdge) {
	if edge.ID == "" || edge.Source == "" || edge.Target == "" || edge.Source == edge.Target {
		return
	}
	if _, ok := b.nodes[edge.Source]; !ok {
		return
	}
	if _, ok := b.nodes[edge.Target]; !ok {
		return
	}
	b.edges[edge.ID] = edge
}

func (b *graphBuilder) prune(limit int) {
	if len(b.nodes) <= limit {
		return
	}
	nodes := b.sortedNodes()
	keep := make(map[string]struct{}, limit)
	for _, node := range nodes[:limit] {
		keep[node.ID] = struct{}{}
	}
	for id := range b.nodes {
		if _, ok := keep[id]; !ok {
			delete(b.nodes, id)
			delete(b.clusterMembers, id)
		}
	}
}

func (b *graphBuilder) rebuildIndexes() {
	b.devicesByMAC = map[string]string{}
	b.apsByBSSID = map[string]string{}
	b.apsBySSID = map[string]string{}
	b.clientsByMAC = map[string]string{}
	for _, node := range b.nodes {
		b.indexNode(node)
	}
}

func (b *graphBuilder) sortedNodes() []GraphNode {
	nodes := make([]GraphNode, 0, len(b.nodes))
	for _, node := range b.nodes {
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		left := graphSortTime(nodes[i])
		right := graphSortTime(nodes[j])
		if left.Equal(right) {
			return nodes[i].ID < nodes[j].ID
		}
		return left.After(right)
	})
	return nodes
}

func (b *graphBuilder) sortedEdges() []GraphResponseEdge {
	edges := make([]GraphResponseEdge, 0, len(b.edges))
	for _, edge := range b.edges {
		edges = append(edges, edge)
	}
	sort.SliceStable(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	return edges
}

func (b *graphBuilder) addLocalEdges() {
	for clusterID, members := range b.clusterMembers {
		if _, ok := b.nodes[clusterID]; !ok {
			continue
		}
		for _, mac := range members {
			deviceID := b.devicesByMAC[graphNorm(mac)]
			if deviceID == "" {
				continue
			}
			b.addEdge(GraphResponseEdge{
				ID:     "cluster_member:" + deviceID + ":" + clusterID,
				Source: deviceID,
				Target: clusterID,
				Kind:   EdgeKindClusterMember,
				Label:  "cluster member",
			})
		}
	}

	for _, node := range b.nodes {
		switch node.Kind {
		case NodeKindClient:
			for _, ap := range b.nodes {
				if ap.Kind != NodeKindAP || graphNorm(node.SSID) == "" || graphNorm(node.SSID) != graphNorm(ap.SSID) {
					continue
				}
				if graphNorm(node.BSSID) != "" && graphNorm(ap.BSSID) != "" && graphNorm(node.BSSID) != graphNorm(ap.BSSID) {
					continue
				}
				b.addEdge(GraphResponseEdge{
					ID:     "association:" + node.ID + ":" + ap.ID,
					Source: node.ID,
					Target: ap.ID,
					Kind:   EdgeKindAssociation,
					Label:  "association",
				})
			}
		case NodeKindShadowAlert:
			deviceID := b.devicesByMAC[graphNorm(node.MAC)]
			if deviceID != "" {
				b.addEdge(GraphResponseEdge{
					ID:     "shadow:" + node.ID + ":" + deviceID,
					Source: node.ID,
					Target: deviceID,
					Kind:   EdgeKindShadow,
					Label:  "shadow alert",
				})
			}
		case NodeKindAlert:
			deviceID := b.devicesByMAC[graphNorm(node.MAC)]
			if deviceID != "" {
				b.addEdge(GraphResponseEdge{
					ID:     "alert_ref:" + node.ID + ":" + deviceID,
					Source: node.ID,
					Target: deviceID,
					Kind:   EdgeKindAlertRef,
					Label:  node.AlertType,
				})
			}
		}
	}
}

func (b *graphBuilder) infraNodeValues() []string {
	seen := map[string]struct{}{}
	for _, node := range b.nodes {
		switch node.Kind {
		case NodeKindDevice, NodeKindClient:
			if key := graphNorm(node.MAC); key != "" {
				seen[key] = struct{}{}
			}
		case NodeKindAP:
			if key := graphNorm(node.BSSID); key != "" {
				seen[key] = struct{}{}
			}
			if key := graphNorm(node.SSID); key != "" {
				seen[key] = struct{}{}
			}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (b *graphBuilder) mapInfraEndpoint(nodeType, value string) string {
	key := graphNorm(value)
	switch nodeType {
	case "bssid":
		if id := b.apsByBSSID[key]; id != "" {
			return id
		}
		return b.devicesByMAC[key]
	case "client_mac":
		if id := b.clientsByMAC[key]; id != "" {
			return id
		}
		return b.devicesByMAC[key]
	case "ssid":
		return b.apsBySSID[key]
	default:
		return ""
	}
}

func fetchGraphDevices(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if filters.SourceMAC != "" {
		add("lower(d.mac_id) = lower($%d)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("d.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("d.last_seen <= $%d", *filters.ObservedBefore)
	}
	if filters.ThreatOnly {
		clauses = append(clauses, `(
EXISTS (SELECT 1 FROM wireless_shadow_alerts s WHERE lower(s.source_mac) = lower(d.mac_id) AND s.resolved_at IS NULL)
OR EXISTS (SELECT 1 FROM vec_alerts a WHERE lower(coalesce(a.source_mac, '')) = lower(d.mac_id) AND a.resolved_at IS NULL)
)`)
	}

	rows, err := tx.Query(ctx, `
SELECT
  d.mac_id,
  coalesce(d.display_name, ''),
  coalesce(d.username, ''),
  coalesce(d.hostname, ''),
  coalesce(d.os_hint, ''),
  d.first_seen,
  d.last_seen
FROM devices d
`+graphWhere(clauses)+`
ORDER BY d.last_seen DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mac, displayName, username, hostname, osHint string
		var firstSeen, lastSeen pgtype.Timestamptz
		if err := rows.Scan(&mac, &displayName, &username, &hostname, &osHint, &firstSeen, &lastSeen); err != nil {
			return err
		}
		label := firstNonEmpty(displayName, hostname, username, mac)
		builder.addNode(GraphNode{
			ID:          graphNodeID(NodeKindDevice, mac),
			Kind:        NodeKindDevice,
			Label:       label,
			MAC:         mac,
			DisplayName: displayName,
			Username:    username,
			Hostname:    hostname,
			OSHint:      osHint,
			FirstSeen:   graphTime(firstSeen),
			LastSeen:    graphTime(lastSeen),
		})
	}
	return rows.Err()
}

func fetchGraphClusters(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if filters.SourceMAC != "" {
		add("lower($%d) = any(c.mac_ids)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("c.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("c.last_seen <= $%d", *filters.ObservedBefore)
	}

	rows, err := tx.Query(ctx, `
SELECT
  c.cluster_id,
  coalesce(c.cluster_name, ''),
  c.mac_ids,
  c.size::integer,
  c.centroid_updated_at,
  c.centroid_sample_count::integer,
  c.first_seen,
  c.last_seen
FROM device_identity_clusters c
`+graphWhere(clauses)+`
ORDER BY c.last_seen DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		var macIDs []string
		var size, centroidSampleCount int32
		var centroidUpdatedAt, firstSeen, lastSeen pgtype.Timestamptz
		if err := rows.Scan(&id, &name, &macIDs, &size, &centroidUpdatedAt, &centroidSampleCount, &firstSeen, &lastSeen); err != nil {
			return err
		}
		nodeID := graphNodeID(NodeKindCluster, fmt.Sprintf("%d", id))
		builder.clusterMembers[nodeID] = macIDs
		builder.addNode(GraphNode{
			ID:                  nodeID,
			Kind:                NodeKindCluster,
			Label:               firstNonEmpty(name, fmt.Sprintf("Cluster %d", id)),
			ClusterSize:         int32Ptr(size),
			CentroidUpdatedAt:   graphTime(centroidUpdatedAt),
			CentroidSampleCount: int32Ptr(centroidSampleCount),
			FirstSeen:           graphTime(firstSeen),
			LastSeen:            graphTime(lastSeen),
		})
	}
	return rows.Err()
}

func fetchGraphAPs(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(awn.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	if filters.SSID != "" {
		add("awn.ssid ilike $%d ESCAPE '\\'", "%"+escapeLike(filters.SSID)+"%")
	}
	if filters.SourceMAC != "" {
		add("lower(coalesce(awn.bssid, '')) = lower($%d)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("awn.updated_at >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("awn.updated_at <= $%d", *filters.ObservedBefore)
	}

	rows, err := tx.Query(ctx, `
SELECT
  awn.id,
  coalesce(awn.ssid, ''),
  coalesce(awn.bssid, ''),
  coalesce(awn.location_id, ''),
  awn.enabled,
  awn.created_at,
  awn.updated_at
FROM wireless_authorized_networks awn
`+graphWhere(clauses)+`
ORDER BY awn.updated_at DESC, awn.id DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ssid, bssid, locationID string
		var enabled bool
		var createdAt, updatedAt pgtype.Timestamptz
		if err := rows.Scan(&id, &ssid, &bssid, &locationID, &enabled, &createdAt, &updatedAt); err != nil {
			return err
		}
		builder.addNode(GraphNode{
			ID:         graphNodeID(NodeKindAP, fmt.Sprintf("%d", id)),
			Kind:       NodeKindAP,
			Label:      firstNonEmpty(ssid, bssid, fmt.Sprintf("AP %d", id)),
			SSID:       ssid,
			BSSID:      bssid,
			LocationID: locationID,
			Enabled:    boolPtr(enabled),
			CreatedAt:  graphTime(createdAt),
			LastSeen:   graphTime(updatedAt),
		})
	}
	return rows.Err()
}

func fetchGraphClients(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(wc.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	if filters.SSID != "" {
		add("wc.ssid ilike $%d ESCAPE '\\'", "%"+escapeLike(filters.SSID)+"%")
	}
	if filters.SourceMAC != "" {
		add("lower(wc.client_mac) = lower($%d)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("wc.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("wc.last_seen <= $%d", *filters.ObservedBefore)
	}

	rows, err := tx.Query(ctx, `
SELECT
  wc.ssid,
  wc.client_mac,
  coalesce(wc.known_bssid, ''),
  wc.first_seen,
  wc.last_seen,
  wc.probe_count::bigint,
  coalesce(wc.location_id, '')
FROM wireless_clients wc
`+graphWhere(clauses)+`
ORDER BY wc.last_seen DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ssid, mac, bssid, locationID string
		var probeCount int64
		var firstSeen, lastSeen pgtype.Timestamptz
		if err := rows.Scan(&ssid, &mac, &bssid, &firstSeen, &lastSeen, &probeCount, &locationID); err != nil {
			return err
		}
		builder.addNode(GraphNode{
			ID:         graphNodeID(NodeKindClient, ssid+"|"+mac),
			Kind:       NodeKindClient,
			Label:      mac,
			MAC:        mac,
			SSID:       ssid,
			BSSID:      bssid,
			LocationID: locationID,
			ProbeCount: int64Ptr(probeCount),
			FirstSeen:  graphTime(firstSeen),
			LastSeen:   graphTime(lastSeen),
		})
	}
	return rows.Err()
}

func fetchGraphShadowAlerts(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(s.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	if len(filters.SensorIDs) > 0 {
		add("coalesce(s.sensor_id, '') = any($%d::text[])", filters.SensorIDs)
	}
	if filters.SSID != "" {
		add("s.ssid ilike $%d ESCAPE '\\'", "%"+escapeLike(filters.SSID)+"%")
	}
	if filters.SourceMAC != "" {
		add("lower(s.source_mac) = lower($%d)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("s.last_occurred_at >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("s.last_occurred_at <= $%d", *filters.ObservedBefore)
	}
	if filters.ThreatOnly {
		clauses = append(clauses, "s.resolved_at IS NULL")
	}

	rows, err := tx.Query(ctx, `
SELECT
  s.source_mac,
  coalesce(s.ssid, ''),
  coalesce(s.sensor_id, ''),
  coalesce(s.location_id, ''),
  s.signal_dbm,
  s.reason,
  s.occurrence_count::bigint,
  s.first_occurred_at,
  s.last_occurred_at,
  s.resolved_at
FROM wireless_shadow_alerts s
`+graphWhere(clauses)+`
ORDER BY s.last_occurred_at DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mac, ssid, sensorID, locationID, reason string
		var signal pgtype.Int4
		var occurrenceCount int64
		var firstSeen, lastSeen, resolvedAt pgtype.Timestamptz
		if err := rows.Scan(&mac, &ssid, &sensorID, &locationID, &signal, &reason, &occurrenceCount, &firstSeen, &lastSeen, &resolvedAt); err != nil {
			return err
		}
		risk := 1.0
		builder.addNode(GraphNode{
			ID:              graphNodeID(NodeKindShadowAlert, mac),
			Kind:            NodeKindShadowAlert,
			Label:           firstNonEmpty(reason, mac),
			MAC:             mac,
			SSID:            ssid,
			SensorID:        sensorID,
			LocationID:      locationID,
			SignalDBM:       int4Ptr(signal),
			RiskScore:       &risk,
			Reason:          reason,
			OccurrenceCount: int64Ptr(occurrenceCount),
			FirstSeen:       graphTime(firstSeen),
			LastSeen:        graphTime(lastSeen),
			ResolvedAt:      graphTime(resolvedAt),
		})
	}
	return rows.Err()
}

func fetchGraphAlerts(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(a.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	if len(filters.SensorIDs) > 0 {
		add("coalesce(a.sensor_id, '') = any($%d::text[])", filters.SensorIDs)
	}
	if filters.SourceMAC != "" {
		add("lower(coalesce(a.source_mac, '')) = lower($%d)", filters.SourceMAC)
	}
	if filters.ObservedAfter != nil {
		add("a.created_at >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("a.created_at <= $%d", *filters.ObservedBefore)
	}
	if filters.ThreatOnly {
		clauses = append(clauses, "a.resolved_at IS NULL")
	}

	rows, err := tx.Query(ctx, `
SELECT
  a.id,
  a.alert_type,
  coalesce(a.source_mac, ''),
  coalesce(a.sensor_id, ''),
  coalesce(a.location_id, ''),
  coalesce(a.score, 0)::double precision,
  a.created_at,
  a.resolved_at
FROM vec_alerts a
`+graphWhere(clauses)+`
ORDER BY a.created_at DESC
LIMIT $1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var alertType, mac, sensorID, locationID string
		var score float64
		var createdAt, resolvedAt pgtype.Timestamptz
		if err := rows.Scan(&id, &alertType, &mac, &sensorID, &locationID, &score, &createdAt, &resolvedAt); err != nil {
			return err
		}
		builder.addNode(GraphNode{
			ID:         graphNodeID(NodeKindAlert, fmt.Sprintf("%d", id)),
			Kind:       NodeKindAlert,
			Label:      firstNonEmpty(alertType, fmt.Sprintf("Alert %d", id)),
			MAC:        mac,
			SensorID:   sensorID,
			LocationID: locationID,
			RiskScore:  float64Ptr(score),
			Score:      float64Ptr(score),
			AlertType:  alertType,
			CreatedAt:  graphTime(createdAt),
			LastSeen:   graphTime(createdAt),
			ResolvedAt: graphTime(resolvedAt),
		})
	}
	return rows.Err()
}

func fetchGraphInfrastructureEdges(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	values := builder.infraNodeValues()
	if len(values) == 0 {
		return nil
	}
	args := []any{values, filters.Limit * 4}
	clauses := []string{"(lower(g.node_a) = any($1::text[]) OR lower(g.node_b) = any($1::text[]))"}
	add := graphClause(&clauses, &args)
	if filters.ObservedAfter != nil {
		add("g.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("g.last_seen <= $%d", *filters.ObservedBefore)
	}

	rows, err := tx.Query(ctx, `
SELECT
  g.node_a,
  g.node_a_type,
  g.node_b,
  g.node_b_type,
  g.edge_type,
  g.weight::double precision
FROM vec_infrastructure_graph g
`+graphWhere(clauses)+`
ORDER BY g.last_seen DESC, g.weight DESC
LIMIT $2`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeA, nodeAType, nodeB, nodeBType, edgeType string
		var weight float64
		if err := rows.Scan(&nodeA, &nodeAType, &nodeB, &nodeBType, &edgeType, &weight); err != nil {
			return err
		}
		source := builder.mapInfraEndpoint(nodeAType, nodeA)
		target := builder.mapInfraEndpoint(nodeBType, nodeB)
		if source == "" || target == "" {
			continue
		}
		kind, ok := graphEdgeKind(edgeType)
		if !ok {
			continue
		}
		builder.addEdge(GraphResponseEdge{
			ID:     "infra:" + string(kind) + ":" + source + ":" + target,
			Source: source,
			Target: target,
			Kind:   kind,
			Weight: float64Ptr(weight),
			Label:  edgeType,
		})
	}
	return rows.Err()
}

func graphClause(clauses *[]string, args *[]any) func(string, any) {
	return func(format string, value any) {
		*args = append(*args, value)
		*clauses = append(*clauses, fmt.Sprintf(format, len(*args)))
	}
}

func graphWhere(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(clauses, " AND ")
}

func graphNodeID(kind NodeKind, value string) string {
	return string(kind) + ":" + strings.TrimSpace(value)
}

func graphNorm(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func graphSortTime(node GraphNode) time.Time {
	for _, value := range []*time.Time{node.LastSeen, node.CreatedAt, node.FirstSeen} {
		if value != nil {
			return value.UTC()
		}
	}
	return time.Time{}
}

func graphTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	next := value.Time.UTC()
	return &next
}

func graphEdgeKind(value string) (EdgeKind, bool) {
	switch value {
	case "association":
		return EdgeKindAssociation, true
	case "probe", "probe_target":
		return EdgeKindProbe, true
	case "rf_proximity":
		return EdgeKindRFProximity, true
	case "roaming":
		return EdgeKindRoaming, true
	case "same_channel":
		return EdgeKindSameChannel, true
	case "vendor_link":
		return EdgeKindVendorLink, true
	default:
		return "", false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolPtr(value bool) *bool {
	return &value
}

func int32Ptr(value int32) *int32 {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func float64Ptr(value float64) *float64 {
	return &value
}

func int4Ptr(value pgtype.Int4) *int32 {
	if !value.Valid {
		return nil
	}
	return &value.Int32
}

func ValidateGraphFilters(filters GraphFilters) error {
	if filters.ObservedAfter != nil && filters.ObservedBefore != nil && filters.ObservedAfter.After(*filters.ObservedBefore) {
		return errors.New("observed_after must be before observed_before")
	}
	return nil
}
