package search

import (
	"context"
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
	inventoryDefaultLimit         = 400
	inventoryMaxLimit             = 1000
	inventoryDefaultMinConfidence = 0.75
	inventoryActiveWindow         = 30 * 24 * time.Hour
)

type InventoryGrouping string

const (
	InventoryGroupingRegistry   InventoryGrouping = "registry"
	InventoryGroupingCMDB       InventoryGrouping = "cmdb"
	InventoryGroupingSimilarity InventoryGrouping = "similarity"
)

type InventoryNodeKind string

const (
	InventoryNodeDevice         InventoryNodeKind = "device"
	InventoryNodeOwner          InventoryNodeKind = "owner"
	InventoryNodeLocationAsset  InventoryNodeKind = "location_asset"
	InventoryNodeCluster        InventoryNodeKind = "cluster"
	InventoryNodeMergeCandidate InventoryNodeKind = "merge_candidate"
)

type InventoryEdgeKind string

const (
	InventoryEdgeOwns           InventoryEdgeKind = "owns"
	InventoryEdgeLocatedAt      InventoryEdgeKind = "located_at"
	InventoryEdgeClusterMember  InventoryEdgeKind = "cluster_member"
	InventoryEdgeMergeCandidate InventoryEdgeKind = "merge_candidate"
	InventoryEdgeSameDevice     InventoryEdgeKind = "same_device"
)

type InventoryFilters struct {
	Grouping           InventoryGrouping `json:"grouping"`
	LocationIDs        []string          `json:"location_ids,omitempty"`
	OwnerIDs           []string          `json:"owner_ids,omitempty"`
	ActiveOnly         bool              `json:"active_only,omitempty"`
	MinDedupConfidence *float64          `json:"min_dedup_confidence,omitempty"`
	Tags               []string          `json:"tags,omitempty"`
	Limit              int               `json:"limit,omitempty"`
}

type InventoryNode struct {
	ID                  string            `json:"id"`
	Kind                InventoryNodeKind `json:"kind"`
	Label               string            `json:"label"`
	MAC                 string            `json:"mac,omitempty"`
	KnownMACs           []string          `json:"known_macs,omitempty"`
	DisplayName         string            `json:"display_name,omitempty"`
	OwnerID             string            `json:"owner_id,omitempty"`
	LocationID          string            `json:"location_id,omitempty"`
	FirstRegistered     *time.Time        `json:"first_registered,omitempty"`
	LastSeen            *time.Time        `json:"last_seen,omitempty"`
	Active              bool              `json:"active"`
	SimilarityClusterID string            `json:"similarity_cluster_id,omitempty"`
	DedupConfidence     *float64          `json:"dedup_confidence,omitempty"`
	Tags                []string          `json:"tags,omitempty"`
}

type InventoryEdge struct {
	ID     string            `json:"id"`
	Source string            `json:"source"`
	Target string            `json:"target"`
	Kind   InventoryEdgeKind `json:"kind"`
	Weight *float64          `json:"weight,omitempty"`
}

type InventoryResponse struct {
	Nodes                []InventoryNode `json:"nodes"`
	Edges                []InventoryEdge `json:"edges"`
	GeneratedAt          time.Time       `json:"generated_at"`
	NodeCount            int             `json:"node_count"`
	EdgeCount            int             `json:"edge_count"`
	TotalRegisteredCount int             `json:"total_registered_count"`
}

type MergeDecision string

const (
	MergeDecisionMerge         MergeDecision = "merge"
	MergeDecisionNotMatch      MergeDecision = "not_match"
	MergeDecisionNeedsMoreData MergeDecision = "needs_more_data"
	MergeDecisionUndoMerge     MergeDecision = "undo_merge"
)

type MergeDecisionRequest struct {
	Decision MergeDecision `json:"decision"`
}

type MergeDecisionResponse struct {
	CandidateID string        `json:"candidate_id"`
	Decision    MergeDecision `json:"decision"`
	Accepted    bool          `json:"accepted"`
	UndoUntil   *time.Time    `json:"undo_until,omitempty"`
}

type inventoryDeviceRow struct {
	MAC         string
	DisplayName string
	OwnerID     string
	Hostname    string
	OSHint      string
	LocationID  string
	FirstSeen   pgtype.Timestamptz
	LastSeen    pgtype.Timestamptz
	Active      bool
	Registered  bool
	Tags        []string
	Cluster     *inventoryClusterRow
}

type inventoryClusterRow struct {
	ID                  int64
	Name                string
	MACs                []string
	Size                int32
	CentroidUpdatedAt   pgtype.Timestamptz
	CentroidSampleCount int32
	FirstSeen           pgtype.Timestamptz
	LastSeen            pgtype.Timestamptz
}

type inventoryCandidateRow struct {
	MACA       string
	MACB       string
	Confidence float64
	ComputedAt pgtype.Timestamptz
}

type inventoryDecisionRecord struct {
	Decision MergeDecision
	At       time.Time
}

func (s *Service) Inventory(ctx context.Context, filters InventoryFilters) (*InventoryResponse, error) {
	filters, err := normalizeInventoryFilters(filters)
	if err != nil {
		return nil, err
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	devices, totalRegisteredCount, err := fetchInventoryDevices(ctx, tx, filters)
	if err != nil {
		return nil, err
	}
	if len(devices) > 0 {
		clusters, err := fetchInventoryClusters(ctx, tx, inventoryDeviceMACs(devices), filters.Limit)
		if err != nil {
			return nil, err
		}
		attachInventoryClusters(devices, clusters)
		devices = filterInventoryDevicesByTags(devices, filters.Tags)
	}

	builder := newInventoryBuilder()
	for _, device := range devices {
		builder.addDevice(device, filters.Grouping)
	}
	if filters.Grouping == InventoryGroupingSimilarity {
		builder.addClusterNodes()
		builder.addClusterMemberEdges()
	}

	if filters.Grouping == InventoryGroupingSimilarity {
		candidates, err := fetchInventoryCandidates(ctx, tx, builder.deviceMACs(), inventoryMinConfidence(filters), filters.Limit)
		if err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			if s.inventoryCandidateSuppressed(inventoryCandidateID(candidate.MACA, candidate.MACB)) {
				continue
			}
			builder.addMergeCandidate(candidate)
		}
	}

	nodes := builder.sortedNodes()
	edges := builder.sortedEdges()
	return &InventoryResponse{
		Nodes:                nodes,
		Edges:                edges,
		GeneratedAt:          time.Now().UTC(),
		NodeCount:            len(nodes),
		EdgeCount:            len(edges),
		TotalRegisteredCount: totalRegisteredCount,
	}, nil
}

func (s *Service) MergeDecision(ctx context.Context, candidateID string, decision MergeDecision) (*MergeDecisionResponse, error) {
	candidateID = strings.TrimSpace(candidateID)
	if candidateID == "" {
		return nil, errors.New("candidate_id is required")
	}
	if !validMergeDecision(decision) {
		return nil, fmt.Errorf("unsupported merge decision %q", decision)
	}

	now := time.Now().UTC()
	if decision == MergeDecisionUndoMerge {
		s.inventoryDecisions.Delete(candidateID)
		return &MergeDecisionResponse{
			CandidateID: candidateID,
			Decision:    decision,
			Accepted:    true,
		}, nil
	}

	s.inventoryDecisions.Store(candidateID, inventoryDecisionRecord{
		Decision: decision,
		At:       now,
	})
	var undoUntil *time.Time
	if decision == MergeDecisionMerge {
		until := now.Add(15 * time.Minute)
		undoUntil = &until
	}
	return &MergeDecisionResponse{
		CandidateID: candidateID,
		Decision:    decision,
		Accepted:    true,
		UndoUntil:   undoUntil,
	}, nil
}

func normalizeInventoryFilters(filters InventoryFilters) (InventoryFilters, error) {
	if filters.Grouping == "" {
		filters.Grouping = InventoryGroupingRegistry
	}
	switch filters.Grouping {
	case InventoryGroupingRegistry, InventoryGroupingCMDB, InventoryGroupingSimilarity:
	default:
		return filters, fmt.Errorf("unsupported inventory grouping %q", filters.Grouping)
	}

	if filters.Limit <= 0 {
		filters.Limit = inventoryDefaultLimit
	}
	if filters.Limit > inventoryMaxLimit {
		filters.Limit = inventoryMaxLimit
	}
	filters.LocationIDs = normalizeGraphList(filters.LocationIDs)
	filters.OwnerIDs = normalizeGraphList(filters.OwnerIDs)
	filters.Tags = normalizeLowerList(filters.Tags)
	if filters.MinDedupConfidence != nil {
		value := *filters.MinDedupConfidence
		if value < 0 {
			value = 0
		}
		if value > 1 {
			value = 1
		}
		filters.MinDedupConfidence = &value
	}
	return filters, nil
}

func inventoryMinConfidence(filters InventoryFilters) float64 {
	if filters.MinDedupConfidence == nil {
		return inventoryDefaultMinConfidence
	}
	return *filters.MinDedupConfidence
}

func fetchInventoryDevices(ctx context.Context, tx pgx.Tx, filters InventoryFilters) ([]*inventoryDeviceRow, int, error) {
	activeAfter := time.Now().UTC().Add(-inventoryActiveWindow)
	args := []any{filters.Limit, activeAfter}
	clauses := []string{}
	add := graphClause(&clauses, &args)
	if len(filters.LocationIDs) > 0 {
		add("coalesce(location_id, '') = any($%d::text[])", filters.LocationIDs)
	}
	if len(filters.OwnerIDs) > 0 {
		add("coalesce(owner_id, '') = any($%d::text[])", filters.OwnerIDs)
	}
	if filters.ActiveOnly {
		clauses = append(clauses, "active")
	}

	rows, err := tx.Query(ctx, `
WITH registered AS (
  SELECT
    d.mac_id AS mac,
    coalesce(d.display_name, '') AS display_name,
    coalesce(nullif(d.username, ''), nullif(inv.registered_username, ''), nullif(inv.username, ''), '') AS owner_id,
    coalesce(nullif(d.hostname, ''), nullif(inv.hostname, ''), '') AS hostname,
    coalesce(d.os_hint, '') AS os_hint,
    coalesce(inv.location_id, '') AS location_id,
    d.first_seen AS first_seen,
    coalesce(inv.last_seen, d.last_seen) AS last_seen,
    true AS registered
  FROM devices d
  LEFT JOIN v_wireless_device_inventory inv ON lower(inv.source_mac) = d.mac_id
),
observed_only AS (
  SELECT
    lower(inv.source_mac) AS mac,
    coalesce(inv.display_name, '') AS display_name,
    coalesce(nullif(inv.registered_username, ''), nullif(inv.username, ''), '') AS owner_id,
    coalesce(inv.hostname, '') AS hostname,
    coalesce(inv.os_hint, '') AS os_hint,
    coalesce(inv.location_id, '') AS location_id,
    inv.first_seen AS first_seen,
    inv.last_seen AS last_seen,
    false AS registered
  FROM v_wireless_device_inventory inv
  LEFT JOIN devices d ON d.mac_id = lower(inv.source_mac)
  WHERE d.mac_id IS NULL
),
all_devices AS (
  SELECT
    *,
    last_seen >= $2::timestamptz AS active
  FROM (
    SELECT * FROM registered
    UNION ALL
    SELECT * FROM observed_only
  ) inventory_source
),
filtered AS (
  SELECT
    *,
    count(*) FILTER (WHERE registered) OVER () AS total_count
  FROM all_devices
  `+graphWhere(clauses)+`
  ORDER BY last_seen DESC NULLS LAST, mac ASC
  LIMIT $1
)
SELECT
  mac,
  display_name,
  owner_id,
  hostname,
  os_hint,
  location_id,
  first_seen,
  last_seen,
  active,
  registered,
  total_count::integer
FROM filtered`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	devices := []*inventoryDeviceRow{}
	total := 0
	for rows.Next() {
		var row inventoryDeviceRow
		if err := rows.Scan(
			&row.MAC,
			&row.DisplayName,
			&row.OwnerID,
			&row.Hostname,
			&row.OSHint,
			&row.LocationID,
			&row.FirstSeen,
			&row.LastSeen,
			&row.Active,
			&row.Registered,
			&total,
		); err != nil {
			return nil, 0, err
		}
		row.Tags = inventoryDeviceTags(&row)
		devices = append(devices, &row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return devices, total, nil
}

func fetchInventoryClusters(ctx context.Context, tx pgx.Tx, macs []string, limit int) (map[string]inventoryClusterRow, error) {
	if len(macs) == 0 {
		return nil, nil
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
WHERE EXISTS (
  SELECT 1
  FROM unnest(c.mac_ids) AS member(mac)
  WHERE lower(member.mac) = any($1::text[])
)
  AND cardinality(c.mac_ids) > 1
ORDER BY c.last_seen DESC, c.cluster_id DESC
LIMIT $2`, macs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byMAC := map[string]inventoryClusterRow{}
	for rows.Next() {
		var row inventoryClusterRow
		if err := rows.Scan(
			&row.ID,
			&row.Name,
			&row.MACs,
			&row.Size,
			&row.CentroidUpdatedAt,
			&row.CentroidSampleCount,
			&row.FirstSeen,
			&row.LastSeen,
		); err != nil {
			return nil, err
		}
		row.MACs = normalizeLowerList(row.MACs)
		if !isDedupedIdentityCluster(row.MACs) {
			continue
		}
		row.Size = int32(len(row.MACs))
		for _, mac := range row.MACs {
			byMAC[mac] = row
		}
	}
	return byMAC, rows.Err()
}

func isDedupedIdentityCluster(macs []string) bool {
	return len(normalizeLowerList(macs)) > 1
}

func fetchInventoryCandidates(ctx context.Context, tx pgx.Tx, macs []string, minConfidence float64, limit int) ([]inventoryCandidateRow, error) {
	if len(macs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
WITH candidate_pairs AS (
  SELECT
    least(lower(left_source_mac), lower(right_source_mac)) AS mac_a,
    greatest(lower(left_source_mac), lower(right_source_mac)) AS mac_b,
    max(cosine_similarity)::double precision AS confidence,
    max(computed_at) AS computed_at
  FROM vec_similarity_pairs_expanded
  WHERE pair_kind IN ('device_device', 'timing_timing')
    AND left_source_mac IS NOT NULL
    AND right_source_mac IS NOT NULL
    AND lower(left_source_mac) <> lower(right_source_mac)
    AND cosine_similarity >= $2
    AND (
      lower(left_source_mac) = any($1::text[])
      OR lower(right_source_mac) = any($1::text[])
    )
  GROUP BY 1, 2
)
SELECT mac_a, mac_b, confidence, computed_at
FROM candidate_pairs
ORDER BY confidence DESC, computed_at DESC, mac_a ASC, mac_b ASC
LIMIT $3`, macs, minConfidence, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := []inventoryCandidateRow{}
	for rows.Next() {
		var row inventoryCandidateRow
		if err := rows.Scan(&row.MACA, &row.MACB, &row.Confidence, &row.ComputedAt); err != nil {
			return nil, err
		}
		candidates = append(candidates, row)
	}
	return candidates, rows.Err()
}

func attachInventoryClusters(devices []*inventoryDeviceRow, clusters map[string]inventoryClusterRow) {
	for _, device := range devices {
		if cluster, ok := clusters[graphNorm(device.MAC)]; ok {
			device.Cluster = &cluster
			device.Tags = inventoryDeviceTags(device)
		}
	}
}

func filterInventoryDevicesByTags(devices []*inventoryDeviceRow, tags []string) []*inventoryDeviceRow {
	if len(tags) == 0 {
		return devices
	}
	out := make([]*inventoryDeviceRow, 0, len(devices))
	for _, device := range devices {
		if inventoryTagsMatch(device.Tags, tags) {
			out = append(out, device)
		}
	}
	return out
}

type inventoryBuilder struct {
	nodes         map[string]InventoryNode
	edges         map[string]InventoryEdge
	devicesByMAC  map[string]InventoryNode
	clusters      map[int64]inventoryClusterRow
	clusterActive map[int64]bool
}

func newInventoryBuilder() *inventoryBuilder {
	return &inventoryBuilder{
		nodes:         map[string]InventoryNode{},
		edges:         map[string]InventoryEdge{},
		devicesByMAC:  map[string]InventoryNode{},
		clusters:      map[int64]inventoryClusterRow{},
		clusterActive: map[int64]bool{},
	}
}

func (b *inventoryBuilder) addDevice(row *inventoryDeviceRow, grouping InventoryGrouping) {
	mac := graphNorm(row.MAC)
	if mac == "" {
		return
	}
	nodeID := inventoryNodeID(InventoryNodeDevice, mac)
	knownMACs := []string{mac}
	clusterID := ""
	if row.Cluster != nil {
		knownMACs = row.Cluster.MACs
		clusterID = inventoryNodeID(InventoryNodeCluster, fmt.Sprintf("%d", row.Cluster.ID))
		if grouping == InventoryGroupingSimilarity {
			b.clusters[row.Cluster.ID] = *row.Cluster
			if row.Active {
				b.clusterActive[row.Cluster.ID] = true
			}
		}
	}
	tags := inventoryDeviceTags(row)
	node := InventoryNode{
		ID:                  nodeID,
		Kind:                InventoryNodeDevice,
		Label:               firstNonEmpty(row.DisplayName, row.Hostname, row.OwnerID, mac),
		MAC:                 mac,
		KnownMACs:           knownMACs,
		DisplayName:         row.DisplayName,
		OwnerID:             row.OwnerID,
		LocationID:          row.LocationID,
		FirstRegistered:     graphTime(row.FirstSeen),
		LastSeen:            graphTime(row.LastSeen),
		Active:              row.Active,
		SimilarityClusterID: clusterID,
		Tags:                tags,
	}
	b.addNode(node)
	b.devicesByMAC[mac] = node

	if grouping == InventoryGroupingCMDB && row.OwnerID != "" {
		ownerID := inventoryNodeID(InventoryNodeOwner, row.OwnerID)
		b.addNode(InventoryNode{
			ID:     ownerID,
			Kind:   InventoryNodeOwner,
			Label:  row.OwnerID,
			Active: true,
			Tags:   []string{"owner", "owner:" + strings.ToLower(row.OwnerID)},
		})
		b.addEdge(InventoryEdge{
			ID:     "owns:" + ownerID + ":" + nodeID,
			Source: ownerID,
			Target: nodeID,
			Kind:   InventoryEdgeOwns,
		})
	}
	if grouping == InventoryGroupingCMDB && row.LocationID != "" {
		locationID := inventoryNodeID(InventoryNodeLocationAsset, row.LocationID)
		b.addNode(InventoryNode{
			ID:         locationID,
			Kind:       InventoryNodeLocationAsset,
			Label:      row.LocationID,
			LocationID: row.LocationID,
			Active:     true,
			Tags:       []string{"location", "location:" + strings.ToLower(row.LocationID)},
		})
		b.addEdge(InventoryEdge{
			ID:     "located_at:" + nodeID + ":" + locationID,
			Source: nodeID,
			Target: locationID,
			Kind:   InventoryEdgeLocatedAt,
		})
	}
}

func (b *inventoryBuilder) addClusterNodes() {
	for _, cluster := range b.clusters {
		nodeID := inventoryNodeID(InventoryNodeCluster, fmt.Sprintf("%d", cluster.ID))
		b.addNode(InventoryNode{
			ID:                  nodeID,
			Kind:                InventoryNodeCluster,
			Label:               firstNonEmpty(cluster.Name, fmt.Sprintf("Cluster %d", cluster.ID)),
			KnownMACs:           cluster.MACs,
			FirstRegistered:     graphTime(cluster.FirstSeen),
			LastSeen:            graphTime(cluster.LastSeen),
			Active:              b.clusterActive[cluster.ID],
			SimilarityClusterID: nodeID,
			Tags:                []string{"cluster", "clustered"},
		})
	}
}

func (b *inventoryBuilder) addClusterMemberEdges() {
	for _, node := range b.devicesByMAC {
		if node.SimilarityClusterID == "" {
			continue
		}
		b.addEdge(InventoryEdge{
			ID:     "cluster_member:" + node.ID + ":" + node.SimilarityClusterID,
			Source: node.ID,
			Target: node.SimilarityClusterID,
			Kind:   InventoryEdgeClusterMember,
		})
	}
}

func (b *inventoryBuilder) addMergeCandidate(row inventoryCandidateRow) {
	left := b.devicesByMAC[graphNorm(row.MACA)]
	right := b.devicesByMAC[graphNorm(row.MACB)]
	if left.ID == "" || right.ID == "" {
		return
	}
	if left.SimilarityClusterID != "" && left.SimilarityClusterID == right.SimilarityClusterID {
		return
	}

	candidateID := inventoryCandidateID(row.MACA, row.MACB)
	confidence := row.Confidence
	clusterID := "similarity:" + graphNorm(row.MACA) + ":" + graphNorm(row.MACB)
	b.addNode(InventoryNode{
		ID:                  candidateID,
		Kind:                InventoryNodeMergeCandidate,
		Label:               left.Label + " / " + right.Label,
		KnownMACs:           []string{graphNorm(row.MACA), graphNorm(row.MACB)},
		LastSeen:            graphTime(row.ComputedAt),
		Active:              true,
		SimilarityClusterID: clusterID,
		DedupConfidence:     &confidence,
		Tags:                []string{"merge-review"},
	})
	for _, target := range []InventoryNode{left, right} {
		b.addEdge(InventoryEdge{
			ID:     "merge_candidate:" + candidateID + ":" + target.ID,
			Source: candidateID,
			Target: target.ID,
			Kind:   InventoryEdgeMergeCandidate,
			Weight: &confidence,
		})
	}
	b.addEdge(InventoryEdge{
		ID:     "same_device:" + left.ID + ":" + right.ID,
		Source: left.ID,
		Target: right.ID,
		Kind:   InventoryEdgeSameDevice,
		Weight: &confidence,
	})
}

func (b *inventoryBuilder) addNode(node InventoryNode) {
	if node.ID == "" {
		return
	}
	b.nodes[node.ID] = node
}

func (b *inventoryBuilder) addEdge(edge InventoryEdge) {
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

func (b *inventoryBuilder) deviceMACs() []string {
	macs := make([]string, 0, len(b.devicesByMAC))
	for mac := range b.devicesByMAC {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}

func (b *inventoryBuilder) sortedNodes() []InventoryNode {
	nodes := make([]InventoryNode, 0, len(b.nodes))
	for _, node := range b.nodes {
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		left := inventorySortTime(nodes[i])
		right := inventorySortTime(nodes[j])
		if left.Equal(right) {
			return nodes[i].ID < nodes[j].ID
		}
		return left.After(right)
	})
	return nodes
}

func (b *inventoryBuilder) sortedEdges() []InventoryEdge {
	edges := make([]InventoryEdge, 0, len(b.edges))
	for _, edge := range b.edges {
		edges = append(edges, edge)
	}
	sort.SliceStable(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	return edges
}

func (s *Service) inventoryCandidateSuppressed(candidateID string) bool {
	value, ok := s.inventoryDecisions.Load(candidateID)
	if !ok {
		return false
	}
	record, ok := value.(inventoryDecisionRecord)
	if !ok {
		s.inventoryDecisions.Delete(candidateID)
		return false
	}
	return record.Decision == MergeDecisionMerge || record.Decision == MergeDecisionNotMatch
}

func inventoryDeviceMACs(devices []*inventoryDeviceRow) []string {
	macs := make([]string, 0, len(devices))
	for _, device := range devices {
		if mac := graphNorm(device.MAC); mac != "" {
			macs = append(macs, mac)
		}
	}
	return normalizeLowerList(macs)
}

func inventoryDeviceTags(device *inventoryDeviceRow) []string {
	tags := []string{"device"}
	if device.Registered {
		tags = append(tags, "registered")
	} else {
		tags = append(tags, "observed")
	}
	if device.Active {
		tags = append(tags, "active")
	} else {
		tags = append(tags, "inactive")
	}
	if device.OwnerID != "" {
		tags = append(tags, "owner:"+strings.ToLower(device.OwnerID))
	}
	if device.LocationID != "" {
		tags = append(tags, "location:"+strings.ToLower(device.LocationID))
	}
	if device.Cluster != nil {
		tags = append(tags, "clustered")
	}
	return normalizeLowerList(tags)
}

func inventoryTagsMatch(values []string, filters []string) bool {
	valueSet := map[string]struct{}{}
	for _, value := range values {
		valueSet[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	for _, filter := range filters {
		if _, ok := valueSet[strings.ToLower(strings.TrimSpace(filter))]; !ok {
			return false
		}
	}
	return true
}

func inventoryNodeID(kind InventoryNodeKind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case InventoryNodeLocationAsset:
		return "location:" + value
	default:
		return string(kind) + ":" + value
	}
}

func inventoryCandidateID(macA, macB string) string {
	macs := normalizeLowerList([]string{macA, macB})
	if len(macs) != 2 {
		return "merge_candidate:" + strings.Join(macs, ":")
	}
	return "merge_candidate:" + macs[0] + ":" + macs[1]
}

func inventorySortTime(node InventoryNode) time.Time {
	for _, value := range []*time.Time{node.LastSeen, node.FirstRegistered} {
		if value != nil {
			return value.UTC()
		}
	}
	return time.Time{}
}

func validMergeDecision(decision MergeDecision) bool {
	switch decision {
	case MergeDecisionMerge, MergeDecisionNotMatch, MergeDecisionNeedsMoreData, MergeDecisionUndoMerge:
		return true
	default:
		return false
	}
}

func (filters InventoryFilters) String() string {
	body, err := json.Marshal(filters)
	if err != nil {
		return "{}"
	}
	return string(body)
}
