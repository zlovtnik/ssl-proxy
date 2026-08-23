package search

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDenseKindQueryKeepsANNLookupUnfiltered(t *testing.T) {
	query := denseKindQuery(vectorTableByKind["event"])
	innerStart := strings.Index(query, "FROM atheros_search.search_vectors_event")
	innerEnd := strings.Index(query, ") nearest")
	require.Greater(t, innerStart, -1)
	require.Greater(t, innerEnd, innerStart)
	inner := query[innerStart:innerEnd]
	require.Contains(t, inner, "ORDER BY embedding <=> $1::vector ASC")
	require.Contains(t, inner, "LIMIT $2")
	require.NotContains(t, inner, "WHERE")
	require.Contains(t, query, "WHERE nearest.embedding_model = $3")
	require.Contains(t, strings.ToLower(query), "::vector")
}

func TestVectorTablesAreFixedByPublicKind(t *testing.T) {
	require.Equal(t, map[string]string{
		"event": "search_vectors_event", "device": "search_vectors_device",
		"behaviour_window": "search_vectors_behaviour", "frame_sequence": "search_vectors_sequence",
	}, vectorTableByKind)
}
