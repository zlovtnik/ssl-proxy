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
	addGraphDeviceSSIDScope(&clauses, &args, "d.mac_id", "lab%net")

	require.Len(t, clauses, 1)
	require.Equal(t, "%lab\\%net%", args[1])
	require.Contains(t, clauses[0], "FROM wireless_clients wc")
	require.Contains(t, clauses[0], "FROM sync_events_expanded se")
	require.Contains(t, clauses[0], "FROM wireless_shadow_alerts s")
	require.Contains(t, clauses[0], "lower(wc.client_mac) = lower(d.mac_id)")
	require.Contains(t, clauses[0], "se.ssid ilike $2")
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
	require.Contains(t, clauses[0], "lower(coalesce(se.source_mac, '')) = lower(member.mac)")
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
	require.Contains(t, sql, "se.stream_name = 'wireless.audit'")
	require.Contains(t, sql, "se.status = 'batched'")
	require.Contains(t, sql, "coalesce(se.location_id, '') = any($3::text[])")
	require.Contains(t, sql, "coalesce(wc.location_id, '') = any($4::text[])")

	eventLimit := strings.Index(sql, "ORDER BY se.observed_at DESC\n  LIMIT $2")
	clientLimit := strings.Index(sql, "ORDER BY wc.last_seen DESC\n  LIMIT $2")
	firstGroup := strings.Index(sql, "GROUP BY ssid, bssid, location_id")
	require.NotEqual(t, -1, eventLimit)
	require.NotEqual(t, -1, clientLimit)
	require.NotEqual(t, -1, firstGroup)
	require.Less(t, eventLimit, firstGroup)
	require.Less(t, clientLimit, firstGroup)
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
