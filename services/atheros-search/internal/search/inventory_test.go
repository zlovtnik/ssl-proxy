package search

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeInventoryFiltersDefaultsAndClamps(t *testing.T) {
	got, err := normalizeInventoryFilters(InventoryFilters{
		Grouping:  InventoryGroupingCMDB,
		LocationIDs: []string{" lab ", "lab", ""},
		OwnerIDs: []string{" security ", "security"},
		Tags:      []string{" Active ", "active"},
		Limit:     5000,
	})
	require.NoError(t, err)
	require.Equal(t, inventoryMaxLimit, got.Limit)
	require.Equal(t, []string{"lab"}, got.LocationIDs)
	require.Equal(t, []string{"security"}, got.OwnerIDs)
	require.Equal(t, []string{"active"}, got.Tags)
}

func TestNormalizeInventoryFiltersRejectsUnsupportedGrouping(t *testing.T) {
	_, err := normalizeInventoryFilters(InventoryFilters{Grouping: "topology"})
	require.ErrorContains(t, err, "unsupported inventory grouping")
}

func TestInventoryDeviceTagsIncludeDerivedOperationalTags(t *testing.T) {
	device := &inventoryDeviceRow{OwnerID: "Security", LocationID: "Floor-2", Active: true, Registered: true}
	require.Equal(t, []string{"device", "registered", "active", "owner:security", "location:floor-2"}, inventoryDeviceTags(device))
}

func TestInventoryGroupingBuildsCMDBEdges(t *testing.T) {
	device := inventoryDeviceRow{MAC: "aa:bb", OwnerID: "security", LocationID: "floor-2", KnownMACs: []string{"aa:bb", "cc:dd"}}
	nodes := map[string]InventoryNode{}
	edges := map[string]InventoryEdge{}
	addInventoryDevice(nodes, edges, device, InventoryGroupingCMDB)
	require.Contains(t, nodes, "owner:security")
	require.Contains(t, nodes, "location:floor-2")
	require.Contains(t, edges, "owns:owner:security:device:aa:bb")
}
