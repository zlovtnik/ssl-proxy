package search

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeInventoryFiltersDefaultsAndClamps(t *testing.T) {
	min := 2.5
	got, err := normalizeInventoryFilters(InventoryFilters{
		Grouping: InventoryGroupingSimilarity, LocationIDs: []string{" lab ", "lab", ""},
		OwnerIDs: []string{" security ", "security"}, Tags: []string{" Active ", "active"},
		Limit: 5000, MinDedupConfidence: &min,
	})
	require.NoError(t, err)
	require.Equal(t, inventoryMaxLimit, got.Limit)
	require.Equal(t, []string{"lab"}, got.LocationIDs)
	require.Equal(t, []string{"security"}, got.OwnerIDs)
	require.Equal(t, []string{"active"}, got.Tags)
	require.Equal(t, 1.0, *got.MinDedupConfidence)
}

func TestNormalizeInventoryFiltersRejectsUnsupportedGrouping(t *testing.T) {
	_, err := normalizeInventoryFilters(InventoryFilters{Grouping: "topology"})
	require.ErrorContains(t, err, "unsupported inventory grouping")
}

func TestInventoryDeviceTagsIncludeDerivedOperationalTags(t *testing.T) {
	device := &inventoryDeviceRow{OwnerID: "Security", LocationID: "Floor-2", Active: true, Registered: true, SimilarityClusterID: "7"}
	require.Equal(t, []string{"device", "registered", "active", "owner:security", "location:floor-2", "clustered"}, inventoryDeviceTags(device))
}

func TestInventoryGroupingBuildsCMDBAndSimilarityEdges(t *testing.T) {
	device := inventoryDeviceRow{MAC: "aa:bb", OwnerID: "security", LocationID: "floor-2", SimilarityClusterID: "7", KnownMACs: []string{"aa:bb", "cc:dd"}}
	nodes := map[string]InventoryNode{}
	edges := map[string]InventoryEdge{}
	addInventoryDevice(nodes, edges, device, InventoryGroupingCMDB)
	require.Contains(t, nodes, "owner:security")
	require.Contains(t, nodes, "location:floor-2")
	require.Contains(t, edges, "owns:owner:security:device:aa:bb")

	nodes = map[string]InventoryNode{}
	edges = map[string]InventoryEdge{}
	addInventoryDevice(nodes, edges, device, InventoryGroupingSimilarity)
	addInventoryClusters(nodes, edges, []inventoryDeviceRow{device})
	require.Contains(t, nodes, "cluster:7")
	require.Contains(t, edges, "cluster_member:device:aa:bb:cluster:7")
}

func TestMergeDecisionValidation(t *testing.T) {
	require.True(t, validMergeDecision(MergeDecisionMerge))
	require.True(t, validMergeDecision(MergeDecisionUndoMerge))
	require.False(t, validMergeDecision(MergeDecision("delete")))
}
