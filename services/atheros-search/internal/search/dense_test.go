package search

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDenseKindQueryKeepsANNLookupUnfiltered(t *testing.T) {
	query := denseKindQuery()
	innerStart := strings.Index(query, "FROM atheros_search.embeddings")
	innerEnd := strings.Index(query, ") nearest")
	require.Greater(t, innerStart, -1)
	require.Greater(t, innerEnd, innerStart)
	inner := query[innerStart:innerEnd]
	require.Contains(t, inner, "ORDER BY embedding <=> $1::public.vector ASC")
	require.Contains(t, inner, "LIMIT $2")
	require.Contains(t, inner, "embedding_model = $3")
	require.Contains(t, inner, "embedding_kind = $4")
	require.Contains(t, query, "JOIN atheros_search.search_documents")
	require.Contains(t, query, "d.status = 'active'")
	require.Contains(t, strings.ToLower(query), "::public.vector")
}
