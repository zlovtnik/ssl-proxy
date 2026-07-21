package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	inventoryDefaultLimit         = 400
	inventoryMaxLimit             = 1000
	inventoryDefaultMinConfidence = 0.75
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
	MAC                 string
	DisplayName         string
	OwnerID             string
	LocationID          string
	FirstRegistered     *time.Time
	LastSeen            *time.Time
	Active              bool
	Registered          bool
	Tags                []string
	SimilarityClusterID string
	DedupConfidence     *float64
	KnownMACs           []string
}

type inventoryCandidateRow struct {
	ID         string
	MACA       string
	MACB       string
	Confidence float64
	ComputedAt *time.Time
}

func (s *Service) Inventory(ctx context.Context, filters InventoryFilters) (*InventoryResponse, error) {
	filters, err := normalizeInventoryFilters(filters)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	devices, err := fetchInventoryDevices(ctx, tx, filters)
	if err != nil {
		return nil, err
	}
	var totalRegistered int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM inventory_devices WHERE registered = 1").Scan(&totalRegistered); err != nil {
		return nil, err
	}

	nodes := map[string]InventoryNode{}
	edges := map[string]InventoryEdge{}
	for _, device := range devices {
		addInventoryDevice(nodes, edges, device, filters.Grouping)
	}
	if filters.Grouping == InventoryGroupingSimilarity {
		addInventoryClusters(nodes, edges, devices)
		candidates, err := fetchInventoryCandidates(ctx, tx, devices, inventoryMinConfidence(filters), filters.Limit)
		if err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			addInventoryCandidate(nodes, edges, candidate)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	sortedNodes := make([]InventoryNode, 0, len(nodes))
	for _, node := range nodes {
		sortedNodes = append(sortedNodes, node)
	}
	sort.Slice(sortedNodes, func(i, j int) bool { return sortedNodes[i].ID < sortedNodes[j].ID })
	sortedEdges := make([]InventoryEdge, 0, len(edges))
	for _, edge := range edges {
		sortedEdges = append(sortedEdges, edge)
	}
	sort.Slice(sortedEdges, func(i, j int) bool { return sortedEdges[i].ID < sortedEdges[j].ID })
	return &InventoryResponse{
		Nodes:                sortedNodes,
		Edges:                sortedEdges,
		GeneratedAt:          time.Now().UTC(),
		NodeCount:            len(sortedNodes),
		EdgeCount:            len(sortedEdges),
		TotalRegisteredCount: totalRegistered,
	}, nil
}

func fetchInventoryDevices(ctx context.Context, tx *sql.Tx, filters InventoryFilters) ([]inventoryDeviceRow, error) {
	clauses := []string{"1 = 1"}
	args := make([]any, 0)
	addInClause(&clauses, &args, "location_id", stringsToAny(filters.LocationIDs))
	addInClause(&clauses, &args, "owner_id", stringsToAny(filters.OwnerIDs))
	if filters.ActiveOnly {
		clauses = append(clauses, "active = 1")
	}
	overfetch := filters.Limit * 4
	if overfetch > 4000 {
		overfetch = 4000
	}
	args = append(args, overfetch)
	rows, err := tx.QueryContext(ctx, `
SELECT
  mac, COALESCE(display_name, ''), COALESCE(owner_id, ''), COALESCE(location_id, ''),
  first_registered, last_seen, active, registered,
  COALESCE(CAST(tags AS CHAR), '[]'), COALESCE(similarity_cluster_id, ''),
  dedup_confidence, COALESCE(CAST(known_macs AS CHAR), '[]')
FROM inventory_devices
WHERE `+strings.Join(clauses, " AND ")+`
ORDER BY last_seen DESC, mac ASC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]inventoryDeviceRow, 0, filters.Limit)
	for rows.Next() {
		var row inventoryDeviceRow
		var first, last sql.NullTime
		var tagsJSON, knownMACsJSON string
		var confidence sql.NullFloat64
		if err := rows.Scan(
			&row.MAC, &row.DisplayName, &row.OwnerID, &row.LocationID,
			&first, &last, &row.Active, &row.Registered,
			&tagsJSON, &row.SimilarityClusterID, &confidence, &knownMACsJSON,
		); err != nil {
			return nil, err
		}
		row.FirstRegistered = nullTimePtr(first)
		row.LastSeen = nullTimePtr(last)
		row.Tags = parseTagsJSON(tagsJSON)
		_ = json.Unmarshal([]byte(knownMACsJSON), &row.KnownMACs)
		if confidence.Valid {
			row.DedupConfidence = &confidence.Float64
		}
		row.Tags = inventoryDeviceTags(&row)
		if !inventoryTagsMatch(row.Tags, filters.Tags) {
			continue
		}
		devices = append(devices, row)
		if len(devices) >= filters.Limit {
			break
		}
	}
	return devices, rows.Err()
}

func fetchInventoryCandidates(ctx context.Context, tx *sql.Tx, devices []inventoryDeviceRow, minConfidence float64, limit int) ([]inventoryCandidateRow, error) {
	if len(devices) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(devices)), ",")
	args := make([]any, 0, len(devices)*2+2)
	for _, device := range devices {
		args = append(args, device.MAC)
	}
	for _, device := range devices {
		args = append(args, device.MAC)
	}
	args = append(args, minConfidence, limit)
	rows, err := tx.QueryContext(ctx, `
SELECT c.candidate_id, c.mac_a, c.mac_b, c.confidence, c.computed_at
FROM merge_candidates c
LEFT JOIN merge_decisions d ON d.candidate_id = c.candidate_id
WHERE c.mac_a IN (`+placeholders+`)
  AND c.mac_b IN (`+placeholders+`)
  AND c.confidence >= ?
  AND c.status = 'pending'
  AND (d.candidate_id IS NULL OR d.decision = 'undo_merge')
ORDER BY c.confidence DESC, c.candidate_id ASC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]inventoryCandidateRow, 0)
	for rows.Next() {
		var row inventoryCandidateRow
		var computed sql.NullTime
		if err := rows.Scan(&row.ID, &row.MACA, &row.MACB, &row.Confidence, &computed); err != nil {
			return nil, err
		}
		row.ComputedAt = nullTimePtr(computed)
		results = append(results, row)
	}
	return results, rows.Err()
}

func (s *Service) MergeDecision(ctx context.Context, candidateID string, decision MergeDecision) (*MergeDecisionResponse, error) {
	candidateID = strings.TrimSpace(candidateID)
	if candidateID == "" {
		return nil, errors.New("candidate_id is required")
	}
	if !validMergeDecision(decision) {
		return nil, fmt.Errorf("unsupported merge decision %q", decision)
	}
	decisionID, err := newUUID()
	if err != nil {
		return nil, err
	}
	result, err := s.Pool.ExecContext(ctx, `
INSERT INTO merge_decisions (
  decision_id, candidate_id, decision, decided_by, evidence, decided_at
)
VALUES (?, ?, ?, 'atheros-search', JSON_OBJECT('source', 'public-api'), UTC_TIMESTAMP(6))
ON DUPLICATE KEY UPDATE
  decision = VALUES(decision),
  decided_by = VALUES(decided_by),
  evidence = VALUES(evidence),
  decided_at = VALUES(decided_at)
`, decisionID, candidateID, string(decision))
	if err != nil {
		return nil, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("merge decision was not persisted")
	}
	response := &MergeDecisionResponse{CandidateID: candidateID, Decision: decision, Accepted: true}
	if decision == MergeDecisionMerge {
		until := time.Now().UTC().Add(15 * time.Minute)
		response.UndoUntil = &until
	}
	return response, nil
}

func addInventoryDevice(nodes map[string]InventoryNode, edges map[string]InventoryEdge, device inventoryDeviceRow, grouping InventoryGrouping) {
	id := "device:" + strings.ToLower(device.MAC)
	label := device.DisplayName
	if label == "" {
		label = device.MAC
	}
	nodes[id] = InventoryNode{
		ID: id, Kind: InventoryNodeDevice, Label: label, MAC: device.MAC,
		KnownMACs: device.KnownMACs, DisplayName: device.DisplayName, OwnerID: device.OwnerID,
		LocationID: device.LocationID, FirstRegistered: device.FirstRegistered, LastSeen: device.LastSeen,
		Active: device.Active, SimilarityClusterID: device.SimilarityClusterID,
		DedupConfidence: device.DedupConfidence, Tags: device.Tags,
	}
	if grouping != InventoryGroupingCMDB {
		return
	}
	if device.OwnerID != "" {
		ownerID := "owner:" + device.OwnerID
		nodes[ownerID] = InventoryNode{ID: ownerID, Kind: InventoryNodeOwner, Label: device.OwnerID, OwnerID: device.OwnerID, Active: true}
		edgeID := "owns:" + ownerID + ":" + id
		edges[edgeID] = InventoryEdge{ID: edgeID, Source: ownerID, Target: id, Kind: InventoryEdgeOwns}
	}
	if device.LocationID != "" {
		locationID := "location:" + device.LocationID
		nodes[locationID] = InventoryNode{ID: locationID, Kind: InventoryNodeLocationAsset, Label: device.LocationID, LocationID: device.LocationID, Active: true}
		edgeID := "located_at:" + id + ":" + locationID
		edges[edgeID] = InventoryEdge{ID: edgeID, Source: id, Target: locationID, Kind: InventoryEdgeLocatedAt}
	}
}

func addInventoryClusters(nodes map[string]InventoryNode, edges map[string]InventoryEdge, devices []inventoryDeviceRow) {
	for _, device := range devices {
		if device.SimilarityClusterID == "" {
			continue
		}
		clusterID := "cluster:" + device.SimilarityClusterID
		node := nodes[clusterID]
		if node.ID == "" {
			node = InventoryNode{ID: clusterID, Kind: InventoryNodeCluster, Label: "Cluster " + device.SimilarityClusterID, Active: true}
		}
		node.KnownMACs = normalizeLowerList(append(node.KnownMACs, device.KnownMACs...))
		nodes[clusterID] = node
		deviceID := "device:" + strings.ToLower(device.MAC)
		edgeID := "cluster_member:" + deviceID + ":" + clusterID
		edges[edgeID] = InventoryEdge{ID: edgeID, Source: deviceID, Target: clusterID, Kind: InventoryEdgeClusterMember}
	}
}

func addInventoryCandidate(nodes map[string]InventoryNode, edges map[string]InventoryEdge, candidate inventoryCandidateRow) {
	id := "merge_candidate:" + candidate.ID
	confidence := candidate.Confidence
	nodes[id] = InventoryNode{ID: id, Kind: InventoryNodeMergeCandidate, Label: candidate.MACA + " / " + candidate.MACB, Active: true, DedupConfidence: &confidence, KnownMACs: []string{candidate.MACA, candidate.MACB}}
	for _, mac := range []string{candidate.MACA, candidate.MACB} {
		deviceID := "device:" + strings.ToLower(mac)
		if _, ok := nodes[deviceID]; !ok {
			continue
		}
		edgeID := "merge_candidate:" + deviceID + ":" + id
		edges[edgeID] = InventoryEdge{ID: edgeID, Source: deviceID, Target: id, Kind: InventoryEdgeMergeCandidate, Weight: &confidence}
	}
}

func inventoryDeviceTags(device *inventoryDeviceRow) []string {
	tags := append([]string{}, device.Tags...)
	tags = append(tags, "device")
	if device.Registered {
		tags = append(tags, "registered")
	}
	if device.Active {
		tags = append(tags, "active")
	}
	if device.OwnerID != "" {
		tags = append(tags, "owner:"+strings.ToLower(device.OwnerID))
	}
	if device.LocationID != "" {
		tags = append(tags, "location:"+strings.ToLower(device.LocationID))
	}
	if device.SimilarityClusterID != "" {
		tags = append(tags, "clustered")
	}
	return normalizeLowerList(tags)
}

func inventoryTagsMatch(actual, required []string) bool {
	for _, tag := range required {
		if !containsFold(actual, tag) {
			return false
		}
	}
	return true
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

func validMergeDecision(decision MergeDecision) bool {
	switch decision {
	case MergeDecisionMerge, MergeDecisionNotMatch, MergeDecisionNeedsMoreData, MergeDecisionUndoMerge:
		return true
	default:
		return false
	}
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}
