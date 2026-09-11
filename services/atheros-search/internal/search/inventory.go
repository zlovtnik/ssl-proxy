package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	inventoryDefaultLimit         = 400
	inventoryMaxLimit             = 1000
)

type InventoryGrouping string

const (
	InventoryGroupingRegistry   InventoryGrouping = "registry"
	InventoryGroupingCMDB       InventoryGrouping = "cmdb"
)

type InventoryNodeKind string

const (
	InventoryNodeDevice         InventoryNodeKind = "device"
	InventoryNodeOwner          InventoryNodeKind = "owner"
	InventoryNodeLocationAsset  InventoryNodeKind = "location_asset"
)

type InventoryEdgeKind string

const (
	InventoryEdgeOwns           InventoryEdgeKind = "owns"
	InventoryEdgeLocatedAt      InventoryEdgeKind = "located_at"
)

type InventoryFilters struct {
	Grouping           InventoryGrouping `json:"grouping"`
	LocationIDs        []string          `json:"location_ids,omitempty"`
	OwnerIDs           []string          `json:"owner_ids,omitempty"`
	ActiveOnly         bool              `json:"active_only,omitempty"`
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
	KnownMACs           []string
}

func (s *Service) Inventory(ctx context.Context, filters InventoryFilters) (*InventoryResponse, error) {
	filters, err := normalizeInventoryFilters(filters)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	devices, err := fetchInventoryDevices(ctx, tx, filters)
	if err != nil {
		return nil, err
	}
	var totalRegistered int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM atheros_search.devices WHERE registered").Scan(&totalRegistered); err != nil {
		return nil, err
	}

	nodes := map[string]InventoryNode{}
	edges := map[string]InventoryEdge{}
	for _, device := range devices {
		addInventoryDevice(nodes, edges, device, filters.Grouping)
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
		clauses = append(clauses, "active")
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
  COALESCE(tags::text, '[]'), COALESCE(known_macs::text, '[]')
FROM atheros_search.devices
WHERE `+strings.Join(clauses, " AND ")+`
ORDER BY last_seen DESC, mac ASC
LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]inventoryDeviceRow, 0, filters.Limit)
	for rows.Next() {
		var row inventoryDeviceRow
		var first, last sql.NullTime
		var tagsJSON, knownMACsJSON string
		if err := rows.Scan(
			&row.MAC, &row.DisplayName, &row.OwnerID, &row.LocationID,
			&first, &last, &row.Active, &row.Registered,
			&tagsJSON, &knownMACsJSON,
		); err != nil {
			return nil, err
		}
		row.FirstRegistered = nullTimePtr(first)
		row.LastSeen = nullTimePtr(last)
		row.Tags = parseTagsJSON(tagsJSON)
		_ = json.Unmarshal([]byte(knownMACsJSON), &row.KnownMACs)
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
		Active: device.Active, Tags: device.Tags,
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
	case InventoryGroupingRegistry, InventoryGroupingCMDB:
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
	return filters, nil
}

func addInClause(clauses *[]string, args *[]any, column string, values []any) {
	if len(values) == 0 {
		return
	}
	start := len(*args) + 1
	placeholders := pgPlaceholders(start, len(values))
	*clauses = append(*clauses, column+" IN ("+placeholders+")")
	*args = append(*args, values...)
}

func pgPlaceholders(start, count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(parts, ",")
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func normalizeGraphList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}
