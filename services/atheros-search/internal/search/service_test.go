package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestSearchRejectsEmptyQuery(t *testing.T) {
	svc := &Service{}
	_, err := svc.Search(context.Background(), &searchv1.SearchRequest{
		Query: "", Kind: searchv1.SearchKind_SEARCH_KIND_CROSS, Mode: searchv1.SearchMode_SEARCH_MODE_SPARSE,
	})
	require.EqualError(t, err, "search query is required and must contain meaningful terms")
}

func TestHasMeaningfulSearchTerms(t *testing.T) {
	for _, test := range []struct {
		query string
		want  bool
	}{
		{"", false}, {"   ", false}, {"*", false}, {"%", false}, {" * % * ", false},
		{"* foo *", true}, {"foo*bar", true},
	} {
		require.Equal(t, test.want, hasMeaningfulSearchTerms(test.query), test.query)
	}
}

func TestIsWildcardAllSearch(t *testing.T) {
	for _, query := range []string{"*", "%", " * % * "} {
		require.True(t, isWildcardAllSearch(query), query)
		require.Equal(t, "%", sparsePattern(query))
	}
	for _, query := range []string{"", "foo*", "* foo *"} {
		require.False(t, isWildcardAllSearch(query), query)
	}
}

func TestSparseTokenPatternsNormalizeAndPreserveSuffixWildcard(t *testing.T) {
	require.Equal(t, []string{"deauth%", "probe_request", "threat:rogue"}, sparseTokenPatterns("Deauth* probe_request threat:rogue"))
	require.Equal(t, []string{"deauth"}, sparseTokenPatterns("deauth deauth"))
}

func TestSuggestSSIDQueryIsUncappedAndMySQLSafe(t *testing.T) {
	require.NotContains(t, suggestSSIDSQL, "LIMIT")
	require.Contains(t, suggestSSIDSQL, "?")
	require.NotContains(t, suggestSSIDSQL, "$1")
}
