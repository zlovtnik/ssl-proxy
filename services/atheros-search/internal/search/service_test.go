package search

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	athmetrics "github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestSearchRejectsEmptyQuery(t *testing.T) {
	registry := prometheus.NewRegistry()
	svc := &Service{Metrics: athmetrics.NewForRegisterer(registry)}
	_, err := svc.Search(context.Background(), &searchv1.SearchRequest{
		Query: "", Kind: searchv1.SearchKind_SEARCH_KIND_CROSS, Mode: searchv1.SearchMode_SEARCH_MODE_SPARSE,
	})
	require.EqualError(t, err, "search query is required and must contain meaningful terms")

	families, gatherErr := registry.Gather()
	require.NoError(t, gatherErr)
	var errorCount float64
	for _, family := range families {
		if family.GetName() != "athsearch_search_requests_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string, len(metric.Label))
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["kind"] == "cross" && labels["mode"] == "sparse" && labels["status"] == "error" {
				errorCount = metric.GetCounter().GetValue()
			}
		}
	}
	require.Equal(t, float64(1), errorCount)
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

func TestSuggestSSIDQueryIsUncappedAndPostgreSQLSafe(t *testing.T) {
	require.NotContains(t, suggestSSIDSQL, "LIMIT")
	require.Contains(t, suggestSSIDSQL, "$1")
}
