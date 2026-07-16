package search

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateGraphFiltersRejectsUnsupportedKinds(t *testing.T) {
	t.Parallel()

	err := ValidateGraphFilters(GraphFilters{
		Kinds: []NodeKind{NodeKindEmbedding},
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported graph node kind")
}

func TestNormalizeGraphFiltersTrimsSSIDAndSortsKinds(t *testing.T) {
	t.Parallel()

	got := normalizeGraphFilters(GraphFilters{
		SSID:  "  lab-net  ",
		Kinds: []NodeKind{NodeKindClient, NodeKindAP, NodeKindClient},
	})

	require.Equal(t, "lab-net", got.SSID)
	require.Equal(t, []NodeKind{NodeKindAP, NodeKindClient}, got.Kinds)
}

func TestGraphDeviceSSIDScopeIncludesWirelessEvidenceSources(t *testing.T) {
	t.Parallel()

	clauses := []string{}
	args := []any{200}
	addGraphDeviceSSIDScope(&clauses, &args, "d.mac_id", "Lab%Net")

	require.Len(t, clauses, 1)
	require.Equal(t, "%lab\\%net%", args[1])
	require.Contains(t, clauses[0], "FROM wireless_clients wc")
	require.Contains(t, clauses[0], "FROM wireless_frames_expanded wf")
	require.Contains(t, clauses[0], "FROM wireless_shadow_alerts s")
	require.Contains(t, clauses[0], "lower(wc.client_mac) = lower(d.mac_id)")
	require.Contains(t, clauses[0], "lower(coalesce(wc.ssid, '')) like $2")
	require.Contains(t, clauses[0], "lower(coalesce(wf.ssid, '')) like $2")
	require.Contains(t, clauses[0], "lower(coalesce(s.ssid, '')) like $2")
	require.NotContains(t, strings.ToLower(clauses[0]), "ilike")
}

func TestGraphClusterSSIDScopeRequiresMemberEvidence(t *testing.T) {
	t.Parallel()

	clauses := []string{}
	args := []any{200}
	addGraphClusterSSIDScope(&clauses, &args, "lab-net")

	require.Len(t, clauses, 1)
	require.Equal(t, "%lab-net%", args[1])
	require.Contains(t, clauses[0], "FROM unnest(c.mac_ids) AS member(mac)")
	require.Contains(t, clauses[0], "lower(wc.client_mac) = lower(member.mac)")
	require.Contains(t, clauses[0], "lower(coalesce(wf.source_mac, '')) = lower(member.mac)")
	require.Contains(t, clauses[0], "lower(s.source_mac) = lower(member.mac)")
}

func TestGraphObservedAPScanLimitBoundsInput(t *testing.T) {
	t.Parallel()

	require.Equal(t, 4000, graphObservedAPScanLimit(0))
	require.Equal(t, 1000, graphObservedAPScanLimit(10))
	require.Equal(t, 4000, graphObservedAPScanLimit(graphDefaultLimit))
	require.Equal(t, 10000, graphObservedAPScanLimit(graphMaxLimit))
}

func TestGraphObservedAPSQLBoundsRecentSourcesBeforeGrouping(t *testing.T) {
	t.Parallel()

	sql, args := graphObservedAPSQL(GraphFilters{
		Limit:       graphDefaultLimit,
		LocationIDs: []string{"lab"},
	})

	require.Equal(t, []any{graphDefaultLimit, 4000, []string{"lab"}, []string{"lab"}}, args)
	require.Contains(t, sql, "WITH recent_event_ap AS")
	require.Contains(t, sql, "FROM sync_events e")
	require.Contains(t, sql, "JOIN wireless_frames wf ON wf.dedupe_key = e.dedupe_key")
	require.Contains(t, sql, "e.stream_name = 'wireless.audit'")
	require.Contains(t, sql, "e.status = 'batched'")
	require.Contains(t, sql, "coalesce(wf.location_id, '') = any($3::text[])")
	require.Contains(t, sql, "coalesce(wc.location_id, '') = any($4::text[])")

	eventLimit := strings.Index(sql, "ORDER BY e.observed_at DESC\n  LIMIT $2")
	clientLimit := strings.Index(sql, "ORDER BY wc.last_seen DESC\n  LIMIT $2")
	firstGroup := strings.Index(sql, "GROUP BY ssid, bssid, location_id")
	require.NotEqual(t, -1, eventLimit)
	require.NotEqual(t, -1, clientLimit)
	require.NotEqual(t, -1, firstGroup)
	require.Less(t, eventLimit, firstGroup)
	require.Less(t, clientLimit, firstGroup)
}

func TestGraphObservedAPSQLUsesIndexedSSIDPredicates(t *testing.T) {
	t.Parallel()

	sql, args := graphObservedAPSQL(GraphFilters{
		Limit: graphDefaultLimit,
		SSID:  "Lab%Net",
	})

	require.Equal(t, []any{graphDefaultLimit, 4000, "%lab\\%net%", "%lab\\%net%"}, args)
	require.Contains(t, sql, "nullif(wf.ssid, '') is not null")
	require.Contains(t, sql, "lower(coalesce(wf.ssid, '')) like $3 ESCAPE '\\'")
	require.Contains(t, sql, "nullif(wc.ssid, '') is not null")
	require.Contains(t, sql, "lower(coalesce(wc.ssid, '')) like $4 ESCAPE '\\'")
	require.NotContains(t, sql, "lower(coalesce(wf.ssid, '')) = any")
	require.NotContains(t, strings.ToLower(sql), "ilike")
	require.NotContains(t, sql, "sync_events_expanded")
}

func TestGraphBuilderPruneDropsClusterWithNoRemainingFetchedMembers(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0).UTC()
	builder := newGraphBuilder()
	clusterID := graphNodeID(NodeKindCluster, "7")
	memberID := graphNodeID(NodeKindDevice, "aa:bb:cc:dd:ee:01")
	unrelatedID := graphNodeID(NodeKindDevice, "aa:bb:cc:dd:ee:02")

	builder.addNode(GraphNode{
		ID:       clusterID,
		Kind:     NodeKindCluster,
		Label:    "Cluster 7",
		LastSeen: timePtr(now.Add(3 * time.Minute)),
	})
	builder.clusterMembers[clusterID] = []string{"aa:bb:cc:dd:ee:01"}
	builder.addNode(GraphNode{
		ID:       unrelatedID,
		Kind:     NodeKindDevice,
		Label:    "unrelated",
		MAC:      "aa:bb:cc:dd:ee:02",
		LastSeen: timePtr(now.Add(2 * time.Minute)),
	})
	builder.addNode(GraphNode{
		ID:       memberID,
		Kind:     NodeKindDevice,
		Label:    "member",
		MAC:      "aa:bb:cc:dd:ee:01",
		LastSeen: timePtr(now.Add(time.Minute)),
	})
	builder.addEdge(GraphResponseEdge{
		ID:     "cluster_member:" + memberID + ":" + clusterID,
		Source: memberID,
		Target: clusterID,
		Kind:   EdgeKindClusterMember,
	})

	builder.prune(2)

	require.Contains(t, builder.nodes, unrelatedID)
	require.NotContains(t, builder.nodes, memberID)
	require.NotContains(t, builder.nodes, clusterID)
	require.NotContains(t, builder.clusterMembers, clusterID)
	require.Empty(t, builder.edges)
}

func TestGraphBuilderPruneKeepsClusterWithRemainingFetchedMember(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0).UTC()
	builder := newGraphBuilder()
	clusterID := graphNodeID(NodeKindCluster, "7")
	keptMemberID := graphNodeID(NodeKindDevice, "aa:bb:cc:dd:ee:01")
	prunedMemberID := graphNodeID(NodeKindDevice, "aa:bb:cc:dd:ee:02")

	builder.addNode(GraphNode{
		ID:       clusterID,
		Kind:     NodeKindCluster,
		Label:    "Cluster 7",
		LastSeen: timePtr(now.Add(3 * time.Minute)),
	})
	builder.clusterMembers[clusterID] = []string{
		"aa:bb:cc:dd:ee:01",
		"aa:bb:cc:dd:ee:02",
	}
	builder.addNode(GraphNode{
		ID:       keptMemberID,
		Kind:     NodeKindDevice,
		Label:    "kept member",
		MAC:      "aa:bb:cc:dd:ee:01",
		LastSeen: timePtr(now.Add(2 * time.Minute)),
	})
	builder.addNode(GraphNode{
		ID:       prunedMemberID,
		Kind:     NodeKindDevice,
		Label:    "pruned member",
		MAC:      "aa:bb:cc:dd:ee:02",
		LastSeen: timePtr(now.Add(time.Minute)),
	})

	builder.prune(2)
	builder.rebuildIndexes()
	builder.addLocalEdges()

	require.Contains(t, builder.nodes, clusterID)
	require.Contains(t, builder.nodes, keptMemberID)
	require.NotContains(t, builder.nodes, prunedMemberID)
	require.Equal(t, []string{"aa:bb:cc:dd:ee:01"}, builder.clusterMembers[clusterID])
	require.Contains(t, builder.edges, "cluster_member:"+keptMemberID+":"+clusterID)
}

func TestPruneExpiredGraphCacheRemovesExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0)
	svc := &Service{}
	svc.graphCache.Store("expired", graphCacheEntry{
		expiresAt: now.Add(-time.Second),
		response:  &GraphResponse{},
	})
	svc.graphCache.Store("fresh", graphCacheEntry{
		expiresAt: now.Add(time.Minute),
		response:  &GraphResponse{},
	})

	svc.pruneExpiredGraphCache(now)

	_, ok := svc.graphCache.Load("expired")
	require.False(t, ok)

	_, ok = svc.graphCache.Load("fresh")
	require.True(t, ok)
}

func timePtr(value time.Time) *time.Time {
	return &value
}
