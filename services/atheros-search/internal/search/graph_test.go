package search

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateGraphFiltersRejectsUnsupportedKinds(t *testing.T) {
	err := ValidateGraphFilters(GraphFilters{Kinds: []NodeKind{NodeKindEmbedding}})
	require.ErrorContains(t, err, "unsupported graph node kind")
}

func TestNormalizeGraphFiltersTrimsAndSorts(t *testing.T) {
	got := normalizeGraphFilters(GraphFilters{
		SSID:  "  lab-net  ",
		Kinds: []NodeKind{NodeKindClient, NodeKindAP, NodeKindClient},
		Limit: 900,
	})
	require.Equal(t, "lab-net", got.SSID)
	require.Equal(t, []NodeKind{NodeKindAP, NodeKindClient}, got.Kinds)
	require.Equal(t, graphMaxLimit, got.Limit)
}

func TestGraphNodesQueryUsesMySQLParametersAndProjectionFilters(t *testing.T) {
	after := time.Unix(100, 0).UTC()
	query, args := graphNodesQuery(normalizeGraphFilters(GraphFilters{
		LocationIDs:   []string{"lab", "hq"},
		SourceMAC:     "AA:BB",
		SSID:          "Lab%Net",
		Kinds:         []NodeKind{NodeKindDevice},
		ThreatOnly:    true,
		ObservedAfter: &after,
		Limit:         50,
	}))
	require.NotContains(t, query, "$1")
	require.NotContains(t, strings.ToLower(query), "unnest")
	require.Contains(t, query, "location_id IN (?,?)")
	require.Contains(t, query, "normalized_ssid LIKE ?")
	require.Contains(t, query, "node_kind IN (?)")
	require.Contains(t, query, "is_threat = 1")
	require.NotContains(t, query, "JSON_EXTRACT")
	require.Equal(t, []any{"hq", "lab", "aa:bb", "%lab\\%net%", "device", after, 50}, args)
}

func TestPruneExpiredGraphCacheRemovesExpiredEntries(t *testing.T) {
	now := time.Unix(1_000, 0)
	svc := &Service{}
	svc.graphCache.Store("expired", graphCacheEntry{expiresAt: now.Add(-time.Second), response: &GraphResponse{}})
	svc.graphCache.Store("fresh", graphCacheEntry{expiresAt: now.Add(time.Minute), response: &GraphResponse{}})
	svc.pruneExpiredGraphCache(now)
	_, ok := svc.graphCache.Load("expired")
	require.False(t, ok)
	_, ok = svc.graphCache.Load("fresh")
	require.True(t, ok)
}
