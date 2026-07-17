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

	graphObservedAPScanMultiplier = 20
	graphObservedAPMinScanLimit   = 1000
	graphObservedAPMaxScanLimit   = 10000
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

	focusMACs   []string
	focusBSSIDs []string
	focusSSIDs  []string
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

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if err := expandGraphFocus(ctx, tx, &filters); err != nil {
		return nil, err
	}

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

func graphFocusMACs(filters GraphFilters) []string {
	values := make([]string, 0, 1+len(filters.focusMACs))
	if filters.SourceMAC != "" {
		values = append(values, filters.SourceMAC)
	}
	values = append(values, filters.focusMACs...)
	return normalizeLowerList(values)
}

func graphFocusBSSIDs(filters GraphFilters) []string {
	values := make([]string, 0, 1+len(filters.focusBSSIDs))
	if filters.SourceMAC != "" {
		values = append(values, filters.SourceMAC)
	}
	values = append(values, filters.focusBSSIDs...)
	return normalizeLowerList(values)
}

func graphFocusSSIDs(filters GraphFilters) []string {
	return normalizeLowerList(filters.focusSSIDs)
}

func graphSSIDLikePattern(ssid string) string {
	return "%" + escapeLike(strings.ToLower(strings.TrimSpace(ssid))) + "%"
}

func graphSSIDContainsClause(expr string, param int) string {
	return fmt.Sprintf("(nullif(%[1]s, '') is not null AND lower(coalesce(%[1]s, '')) like $%[2]d ESCAPE '\\')", expr, param)
}

func addGraphSSIDContains(clauses *[]string, args *[]any, expr string, ssid string) {
	if strings.TrimSpace(ssid) == "" {
		return
	}
	*args = append(*args, graphSSIDLikePattern(ssid))
	*clauses = append(*clauses, graphSSIDContainsClause(expr, len(*args)))
}

func graphObservedAPScanLimit(limit int) int {
	if limit <= 0 {
		limit = graphDefaultLimit
	}
	scanLimit := limit * graphObservedAPScanMultiplier
	if scanLimit < graphObservedAPMinScanLimit {
		return graphObservedAPMinScanLimit
	}
	if scanLimit > graphObservedAPMaxScanLimit {
		return graphObservedAPMaxScanLimit
	}
	return scanLimit
}

func graphDeviceSSIDScopeClause(macExpr string, param int) string {
	return fmt.Sprintf(`(
EXISTS (
  SELECT 1
  FROM wireless_clients wc
  WHERE lower(wc.client_mac) = lower(%[1]s)
    AND %[3]s
)
OR EXISTS (
  SELECT 1
  FROM wireless_frames_expanded wf
  WHERE lower(coalesce(wf.source_mac, '')) = lower(%[1]s)
    AND %[4]s
)
OR EXISTS (
  SELECT 1
  FROM wireless_shadow_alerts s
  WHERE lower(s.source_mac) = lower(%[1]s)
    AND %[5]s
)
)`, macExpr, param, graphSSIDContainsClause("wc.ssid", param), graphSSIDContainsClause("wf.ssid", param), graphSSIDContainsClause("s.ssid", param))
}

func addGraphDeviceSSIDScope(clauses *[]string, args *[]any, macExpr string, ssid string) {
	if strings.TrimSpace(ssid) == "" {
		return
	}
	*args = append(*args, graphSSIDLikePattern(ssid))
	*clauses = append(*clauses, graphDeviceSSIDScopeClause(macExpr, len(*args)))
}

func graphClusterSSIDScopeClause(param int) string {
	return fmt.Sprintf(`EXISTS (
  SELECT 1
  FROM unnest(c.mac_ids) AS member(mac)
  WHERE %s
)`, graphDeviceSSIDScopeClause("member.mac", param))
}

func addGraphClusterSSIDScope(clauses *[]string, args *[]any, ssid string) {
	if strings.TrimSpace(ssid) == "" {
		return
	}
	*args = append(*args, graphSSIDLikePattern(ssid))
	*clauses = append(*clauses, graphClusterSSIDScopeClause(len(*args)))
}

func expandGraphFocus(ctx context.Context, tx pgx.Tx, filters *GraphFilters) error {
	if filters.SourceMAC == "" {
		return nil
	}

	limit := filters.Limit * 4
	if limit < graphDefaultLimit {
		limit = graphDefaultLimit
	}
	macs := normalizeLowerList([]string{filters.SourceMAC})
	bssids := normalizeLowerList([]string{filters.SourceMAC})
	ssids := []string{}

	addMAC := func(value string) {
		macs = normalizeLowerList(append(macs, value))
	}
	addBSSID := func(value string) {
		bssids = normalizeLowerList(append(bssids, value))
	}
	addSSID := func(value string) {
		ssids = normalizeLowerList(append(ssids, value))
	}

	rows, err := tx.Query(ctx, `
SELECT c.mac_ids
FROM device_identity_clusters c
WHERE EXISTS (
  SELECT 1
  FROM unnest(c.mac_ids) AS member(mac)
  WHERE lower(member.mac) = any($1::text[])
)
ORDER BY c.last_seen DESC
LIMIT $2`, macs, limit)
	if err != nil {
		return err
	}
	for rows.Next() {
		var clusterMACs []string
		if err := rows.Scan(&clusterMACs); err != nil {
			rows.Close()
			return err
		}
		for _, mac := range clusterMACs {
			addMAC(mac)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	clientMACs := normalizeLowerList(append([]string{filters.SourceMAC}, macs...))
	clientBSSIDs := normalizeLowerList(append([]string{filters.SourceMAC}, bssids...))
	rows, err = tx.Query(ctx, `
SELECT
  coalesce(wc.client_mac, ''),
  coalesce(wc.known_bssid, ''),
  coalesce(wc.ssid, '')
FROM wireless_clients wc
WHERE lower(coalesce(wc.client_mac, '')) = any($1::text[])
   OR lower(coalesce(wc.known_bssid, '')) = any($2::text[])
ORDER BY wc.last_seen DESC
LIMIT $3`, clientMACs, clientBSSIDs, limit)
	if err != nil {
		return err
	}
	for rows.Next() {
		var clientMAC, bssid, ssid string
		if err := rows.Scan(&clientMAC, &bssid, &ssid); err != nil {
			rows.Close()
			return err
		}
		addMAC(clientMAC)
		addBSSID(bssid)
		addSSID(ssid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	matchMACs := normalizeLowerList(append(append([]string{}, macs...), bssids...))
	rows, err = tx.Query(ctx, `
SELECT
  coalesce(se.source_mac, ''),
  coalesce(se.bssid, se.destination_bssid, ''),
  coalesce(se.ssid, '')
FROM sync_events_expanded se
WHERE lower(coalesce(se.source_mac, '')) = any($1::text[])
   OR lower(coalesce(se.bssid, se.destination_bssid, '')) = any($1::text[])
ORDER BY se.observed_at DESC
LIMIT $2`, matchMACs, limit)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sourceMAC, bssid, ssid string
		if err := rows.Scan(&sourceMAC, &bssid, &ssid); err != nil {
			rows.Close()
			return err
		}
		addMAC(sourceMAC)
		addBSSID(bssid)
		addSSID(ssid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
SELECT
  coalesce(awn.bssid, ''),
  coalesce(awn.ssid, '')
FROM wireless_authorized_networks awn
WHERE lower(coalesce(awn.bssid, '')) = any($1::text[])
   OR lower(coalesce(awn.ssid, '')) = any($2::text[])
ORDER BY awn.updated_at DESC
LIMIT $3`, bssids, ssids, limit)
	if err != nil {
		return err
	}
	for rows.Next() {
		var bssid, ssid string
		if err := rows.Scan(&bssid, &ssid); err != nil {
			rows.Close()
			return err
		}
		addBSSID(bssid)
		addSSID(ssid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	filters.focusMACs = macs
	filters.focusBSSIDs = bssids
	filters.focusSSIDs = ssids
	return nil
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
	graphDeviceMACs := map[string]struct{}{}
	keptDeviceMACs := map[string]struct{}{}
	for _, node := range b.nodes {
		if node.Kind != NodeKindDevice {
			continue
		}
		key := graphNorm(node.MAC)
		if key == "" {
			continue
		}
		graphDeviceMACs[key] = struct{}{}
		if _, ok := keep[node.ID]; ok {
			keptDeviceMACs[key] = struct{}{}
		}
	}
	for id := range b.nodes {
		if _, ok := keep[id]; !ok {
			delete(b.nodes, id)
			delete(b.clusterMembers, id)
		}
	}
	b.pruneClusterMembers(graphDeviceMACs, keptDeviceMACs)
	b.pruneEdges()
}

func (b *graphBuilder) pruneClusterMembers(graphDeviceMACs, keptDeviceMACs map[string]struct{}) {
	for clusterID, members := range b.clusterMembers {
		if _, ok := b.nodes[clusterID]; !ok {
			delete(b.clusterMembers, clusterID)
			continue
		}

		hadGraphMember := false
		keptMembers := members[:0]
		for _, mac := range members {
			key := graphNorm(mac)
			if key == "" {
				continue
			}
			if _, ok := graphDeviceMACs[key]; ok {
				hadGraphMember = true
			}
			if _, ok := keptDeviceMACs[key]; ok {
				keptMembers = append(keptMembers, mac)
			}
		}
		if !hadGraphMember {
			continue
		}
		if len(keptMembers) == 0 {
			delete(b.nodes, clusterID)
			delete(b.clusterMembers, clusterID)
			continue
		}
		b.clusterMembers[clusterID] = keptMembers
	}
}

func (b *graphBuilder) pruneEdges() {
	for id, edge := range b.edges {
		if _, ok := b.nodes[edge.Source]; !ok {
			delete(b.edges, id)
			continue
		}
		if _, ok := b.nodes[edge.Target]; !ok {
			delete(b.edges, id)
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
	if sourceMACs := graphFocusMACs(filters); len(sourceMACs) > 0 {
		add("lower(d.mac_id) = any($%d::text[])", sourceMACs)
	}
	addGraphDeviceSSIDScope(&clauses, &args, "d.mac_id", filters.SSID)
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
			ID:               graphNodeID(NodeKindDevice, mac),
			Kind:             NodeKindDevice,
			Label:            label,
			MAC:              mac,
			DisplayName:      displayName,
			Username:         username,
			Hostname:         hostname,
			OSHint:           osHint,
			FirstSeen:        graphTime(firstSeen),
			LastSeen:         graphTime(lastSeen),
			EventSourceMACs:  graphActionMACs(mac),
			ExplainSourceKey: mac,
			ExplainKind:      "SEARCH_KIND_DEVICE",
		})
	}
	return rows.Err()
}

func fetchGraphClusters(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if sourceMACs := graphFocusMACs(filters); len(sourceMACs) > 0 {
		add(`EXISTS (
  SELECT 1
  FROM unnest(c.mac_ids) AS member(mac)
  WHERE lower(member.mac) = any($%d::text[])
)`, sourceMACs)
	}
	addGraphClusterSSIDScope(&clauses, &args, filters.SSID)
	if filters.ObservedAfter != nil {
		add("c.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		add("c.last_seen <= $%d", *filters.ObservedBefore)
	}
	clauses = append(clauses, "cardinality(c.mac_ids) > 1")

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
		macIDs = normalizeLowerList(macIDs)
		if !isDedupedIdentityCluster(macIDs) {
			continue
		}
		size = int32(len(macIDs))
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
			EventSourceMACs:     normalizeLowerList(macIDs),
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
	addGraphSSIDContains(&clauses, &args, "awn.ssid", filters.SSID)
	sourceBSSIDs := graphFocusBSSIDs(filters)
	focusSSIDs := graphFocusSSIDs(filters)
	if len(sourceBSSIDs) > 0 || len(focusSSIDs) > 0 {
		parts := []string{}
		if len(sourceBSSIDs) > 0 {
			args = append(args, sourceBSSIDs)
			parts = append(parts, fmt.Sprintf("lower(coalesce(awn.bssid, '')) = any($%d::text[])", len(args)))
		}
		if len(focusSSIDs) > 0 {
			args = append(args, focusSSIDs)
			parts = append(parts, fmt.Sprintf("lower(coalesce(awn.ssid, '')) = any($%d::text[])", len(args)))
		}
		clauses = append(clauses, "("+strings.Join(parts, " OR ")+")")
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
			EventSSIDs: graphActionStrings(ssid),
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}

	return fetchGraphObservedAPs(ctx, tx, filters, builder)
}

func fetchGraphObservedAPs(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	sql, args := graphObservedAPSQL(filters)
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ssid, bssid, locationID string
		var firstSeen, lastSeen pgtype.Timestamptz
		if err := rows.Scan(&ssid, &bssid, &locationID, &firstSeen, &lastSeen); err != nil {
			return err
		}
		if existing := builder.apsByBSSID[graphNorm(bssid)]; existing != "" {
			continue
		}
		nodeKey := strings.Join([]string{ssid, bssid, locationID}, "|")
		builder.addNode(GraphNode{
			ID:         graphNodeID(NodeKindAP, "observed:"+nodeKey),
			Kind:       NodeKindAP,
			Label:      firstNonEmpty(ssid, bssid, "Observed AP"),
			SSID:       ssid,
			BSSID:      bssid,
			LocationID: locationID,
			FirstSeen:  graphTime(firstSeen),
			LastSeen:   graphTime(lastSeen),
			EventSSIDs: graphActionStrings(ssid),
		})
	}
	return rows.Err()
}

func graphObservedAPSQL(filters GraphFilters) (string, []any) {
	limit := filters.Limit
	if limit <= 0 {
		limit = graphDefaultLimit
	}
	if limit > graphMaxLimit {
		limit = graphMaxLimit
	}
	args := []any{limit, graphObservedAPScanLimit(limit)}
	eventClauses := []string{
		"e.stream_name = 'wireless.audit'",
		"e.status = 'batched'",
		"coalesce(wf.bssid, wf.destination_bssid, '') <> ''",
	}
	clientClauses := []string{"coalesce(wc.known_bssid, '') <> ''"}
	addEvent := graphClause(&eventClauses, &args)
	addClient := graphClause(&clientClauses, &args)

	if len(filters.LocationIDs) > 0 {
		addEvent("coalesce(wf.location_id, '') = any($%d::text[])", filters.LocationIDs)
		addClient("coalesce(wc.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	addGraphSSIDContains(&eventClauses, &args, "wf.ssid", filters.SSID)
	addGraphSSIDContains(&clientClauses, &args, "wc.ssid", filters.SSID)

	sourceBSSIDs := graphFocusBSSIDs(filters)
	focusSSIDs := graphFocusSSIDs(filters)
	if len(sourceBSSIDs) > 0 || len(focusSSIDs) > 0 {
		eventParts := []string{}
		clientParts := []string{}
		if len(sourceBSSIDs) > 0 {
			args = append(args, sourceBSSIDs)
			param := len(args)
			eventParts = append(eventParts, fmt.Sprintf("lower(coalesce(wf.bssid, wf.destination_bssid, '')) = any($%d::text[])", param))
			clientParts = append(clientParts, fmt.Sprintf("lower(coalesce(wc.known_bssid, '')) = any($%d::text[])", param))
		}
		if len(focusSSIDs) > 0 {
			args = append(args, focusSSIDs)
			param := len(args)
			eventParts = append(eventParts, fmt.Sprintf("lower(coalesce(wf.ssid, '')) = any($%d::text[])", param))
			clientParts = append(clientParts, fmt.Sprintf("lower(coalesce(wc.ssid, '')) = any($%d::text[])", param))
		}
		eventClauses = append(eventClauses, "("+strings.Join(eventParts, " OR ")+")")
		clientClauses = append(clientClauses, "("+strings.Join(clientParts, " OR ")+")")
	}
	if filters.ObservedAfter != nil {
		addEvent("e.observed_at >= $%d", *filters.ObservedAfter)
		addClient("wc.last_seen >= $%d", *filters.ObservedAfter)
	}
	if filters.ObservedBefore != nil {
		addEvent("e.observed_at <= $%d", *filters.ObservedBefore)
		addClient("wc.last_seen <= $%d", *filters.ObservedBefore)
	}

	sql := fmt.Sprintf(`
WITH recent_event_ap AS (
  SELECT
    coalesce(wf.ssid, '') AS ssid,
    lower(coalesce(wf.bssid, wf.destination_bssid, '')) AS bssid,
    coalesce(wf.location_id, '') AS location_id,
    e.observed_at AS first_seen,
    e.observed_at AS last_seen
  FROM sync_events e
  JOIN wireless_frames wf ON wf.dedupe_key = e.dedupe_key
  %s
  ORDER BY e.observed_at DESC
  LIMIT $2
),
recent_client_ap AS (
  SELECT
    coalesce(wc.ssid, '') AS ssid,
    lower(coalesce(wc.known_bssid, '')) AS bssid,
    coalesce(wc.location_id, '') AS location_id,
    wc.first_seen,
    wc.last_seen
  FROM wireless_clients wc
  %s
  ORDER BY wc.last_seen DESC
  LIMIT $2
),
observed_ap AS (
  SELECT
    ssid,
    bssid,
    location_id,
    min(first_seen) AS first_seen,
    max(last_seen) AS last_seen
  FROM recent_event_ap
  GROUP BY ssid, bssid, location_id

  UNION ALL

  SELECT
    ssid,
    bssid,
    location_id,
    min(first_seen) AS first_seen,
    max(last_seen) AS last_seen
  FROM recent_client_ap
  GROUP BY ssid, bssid, location_id
)
SELECT
  ssid,
  bssid,
  location_id,
  min(first_seen),
  max(last_seen)
FROM observed_ap
GROUP BY ssid, bssid, location_id
ORDER BY max(last_seen) DESC
LIMIT $1`, graphWhere(eventClauses), graphWhere(clientClauses))
	return sql, args
}

func fetchGraphClients(ctx context.Context, tx pgx.Tx, filters GraphFilters, builder *graphBuilder) error {
	args := []any{filters.Limit}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(wc.location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	addGraphSSIDContains(&clauses, &args, "wc.ssid", filters.SSID)
	sourceMACs := graphFocusMACs(filters)
	sourceBSSIDs := graphFocusBSSIDs(filters)
	focusSSIDs := graphFocusSSIDs(filters)
	if len(sourceMACs) > 0 || len(sourceBSSIDs) > 0 || len(focusSSIDs) > 0 {
		parts := []string{}
		if len(sourceMACs) > 0 {
			args = append(args, sourceMACs)
			parts = append(parts, fmt.Sprintf("lower(wc.client_mac) = any($%d::text[])", len(args)))
		}
		if len(sourceBSSIDs) > 0 {
			args = append(args, sourceBSSIDs)
			parts = append(parts, fmt.Sprintf("lower(coalesce(wc.known_bssid, '')) = any($%d::text[])", len(args)))
		}
		if len(focusSSIDs) > 0 {
			args = append(args, focusSSIDs)
			parts = append(parts, fmt.Sprintf("lower(coalesce(wc.ssid, '')) = any($%d::text[])", len(args)))
		}
		clauses = append(clauses, "("+strings.Join(parts, " OR ")+")")
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
			ID:               graphNodeID(NodeKindClient, ssid+"|"+mac),
			Kind:             NodeKindClient,
			Label:            mac,
			MAC:              mac,
			SSID:             ssid,
			BSSID:            bssid,
			LocationID:       locationID,
			ProbeCount:       int64Ptr(probeCount),
			FirstSeen:        graphTime(firstSeen),
			LastSeen:         graphTime(lastSeen),
			EventSourceMACs:  graphActionMACs(mac),
			EventSSIDs:       graphActionStrings(ssid),
			ExplainSourceKey: mac,
			ExplainKind:      "SEARCH_KIND_DEVICE",
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
	addGraphSSIDContains(&clauses, &args, "s.ssid", filters.SSID)
	if sourceMACs := graphFocusMACs(filters); len(sourceMACs) > 0 {
		add("lower(s.source_mac) = any($%d::text[])", sourceMACs)
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
			EventSourceMACs: graphActionMACs(mac),
			EventSSIDs:      graphActionStrings(ssid),
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
	if sourceMACs := graphFocusMACs(filters); len(sourceMACs) > 0 {
		add("lower(coalesce(a.source_mac, '')) = any($%d::text[])", sourceMACs)
	}
	addGraphDeviceSSIDScope(&clauses, &args, "coalesce(a.source_mac, '')", filters.SSID)
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
			ID:              graphNodeID(NodeKindAlert, fmt.Sprintf("%d", id)),
			Kind:            NodeKindAlert,
			Label:           firstNonEmpty(alertType, fmt.Sprintf("Alert %d", id)),
			MAC:             mac,
			SensorID:        sensorID,
			LocationID:      locationID,
			RiskScore:       float64Ptr(score),
			Score:           float64Ptr(score),
			AlertType:       alertType,
			CreatedAt:       graphTime(createdAt),
			LastSeen:        graphTime(createdAt),
			ResolvedAt:      graphTime(resolvedAt),
			EventSourceMACs: graphActionMACs(mac),
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

func graphActionMACs(values ...string) []string {
	return normalizeLowerList(values)
}

func graphActionStrings(values ...string) []string {
	out := normalizeLowerList(values)
	if len(out) == 0 {
		return nil
	}
	return out
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
	for _, kind := range filters.Kinds {
		if !validGraphNodeKind(kind) {
			return fmt.Errorf("unsupported graph node kind %q", kind)
		}
	}
	return nil
}
