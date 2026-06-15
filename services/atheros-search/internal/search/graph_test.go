package search

import (
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
