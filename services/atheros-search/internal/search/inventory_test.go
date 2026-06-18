package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeInventoryFiltersDefaultsAndClamps(t *testing.T) {
	t.Parallel()

	min := 2.5
	got, err := normalizeInventoryFilters(InventoryFilters{
		Grouping:           InventoryGroupingSimilarity,
		LocationIDs:        []string{" lab ", "lab", ""},
		OwnerIDs:           []string{" security ", "security"},
		Tags:               []string{" Active ", "active"},
		Limit:              5000,
		MinDedupConfidence: &min,
	})

	require.NoError(t, err)
	require.Equal(t, InventoryGroupingSimilarity, got.Grouping)
	require.Equal(t, inventoryMaxLimit, got.Limit)
	require.Equal(t, []string{"lab"}, got.LocationIDs)
	require.Equal(t, []string{"security"}, got.OwnerIDs)
	require.Equal(t, []string{"active"}, got.Tags)
	require.NotNil(t, got.MinDedupConfidence)
	require.Equal(t, 1.0, *got.MinDedupConfidence)
}

func TestNormalizeInventoryFiltersRejectsUnsupportedGrouping(t *testing.T) {
	t.Parallel()

	_, err := normalizeInventoryFilters(InventoryFilters{Grouping: "topology"})
	require.ErrorContains(t, err, "unsupported inventory grouping")
}

func TestInventoryDeviceTagsIncludeDerivedOperationalTags(t *testing.T) {
	t.Parallel()

	device := &inventoryDeviceRow{
		OwnerID:    "Security",
		LocationID: "Floor-2",
		Active:     true,
		Registered: true,
		Cluster:    &inventoryClusterRow{ID: 7},
	}

	require.Equal(t, []string{
		"device",
		"registered",
		"active",
		"owner:security",
		"location:floor-2",
		"clustered",
	}, inventoryDeviceTags(device))
	require.True(t, inventoryTagsMatch(device.Tags, nil))
}

func TestInventoryBuilderAppliesGrouping(t *testing.T) {
	t.Parallel()

	device := &inventoryDeviceRow{
		MAC:        "aa:bb:cc:dd:ee:01",
		OwnerID:    "security",
		LocationID: "floor-2",
		Active:     true,
		Registered: true,
		Cluster: &inventoryClusterRow{
			ID:   7,
			MACs: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
		},
	}

	registry := newInventoryBuilder()
	registry.addDevice(device, InventoryGroupingRegistry)
	require.Len(t, registry.nodes, 1)
	require.Empty(t, registry.edges)

	cmdb := newInventoryBuilder()
	cmdb.addDevice(device, InventoryGroupingCMDB)
	require.Contains(t, cmdb.nodes, "owner:security")
	require.Contains(t, cmdb.nodes, "location:floor-2")
	require.Contains(t, cmdb.edges, "owns:owner:security:device:aa:bb:cc:dd:ee:01")
	require.Contains(t, cmdb.edges, "located_at:device:aa:bb:cc:dd:ee:01:location:floor-2")
	require.NotContains(t, cmdb.nodes, "cluster:7")

	similarity := newInventoryBuilder()
	similarity.addDevice(device, InventoryGroupingSimilarity)
	similarity.addClusterNodes()
	similarity.addClusterMemberEdges()
	require.Contains(t, similarity.nodes, "cluster:7")
	require.Contains(t, similarity.edges, "cluster_member:device:aa:bb:cc:dd:ee:01:cluster:7")
	require.NotContains(t, similarity.nodes, "owner:security")
	require.NotContains(t, similarity.nodes, "location:floor-2")
}

func TestMergeDecisionSuppressesCandidateUntilUndo(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	candidateID := inventoryCandidateID("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")

	require.False(t, svc.inventoryCandidateSuppressed(candidateID))
	resp, err := svc.MergeDecision(context.Background(), candidateID, MergeDecisionMerge)
	require.NoError(t, err)
	require.True(t, resp.Accepted)
	require.Equal(t, candidateID, resp.CandidateID)
	require.NotNil(t, resp.UndoUntil)
	require.True(t, svc.inventoryCandidateSuppressed(candidateID))

	resp, err = svc.MergeDecision(context.Background(), candidateID, MergeDecisionUndoMerge)
	require.NoError(t, err)
	require.True(t, resp.Accepted)
	require.False(t, svc.inventoryCandidateSuppressed(candidateID))
}

func TestMergeDecisionRejectsUnsupportedDecision(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	_, err := svc.MergeDecision(context.Background(), "candidate", MergeDecision("delete"))
	require.ErrorContains(t, err, "unsupported merge decision")
}
