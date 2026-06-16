package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestSearchRejectsEmptyQuery(t *testing.T) {
	t.Parallel()

	svc := &Service{}

	_, err := svc.Search(context.Background(), &searchv1.SearchRequest{
		Query: "",
		Kind:  searchv1.SearchKind_SEARCH_KIND_CROSS,
		Mode:  searchv1.SearchMode_SEARCH_MODE_SPARSE,
	})

	require.Error(t, err)
	require.Equal(t, "search query is required and must contain meaningful terms", err.Error())
}

func TestHasMeaningfulSearchTerms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "empty", query: "", want: false},
		{name: "spaces", query: "   ", want: false},
		{name: "wildcard", query: "*", want: false},
		{name: "percent", query: "%", want: false},
		{name: "wildcard phrase", query: " * % * ", want: false},
		{name: "trimmed term", query: "* foo *", want: true},
		{name: "inline wildcard", query: "foo*bar", want: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, hasMeaningfulSearchTerms(tc.query))
		})
	}
}

func TestIsWildcardAllSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "empty", query: "", want: false},
		{name: "spaces", query: "   ", want: false},
		{name: "star", query: "*", want: true},
		{name: "percent", query: "%", want: true},
		{name: "mixed wildcards", query: " * % * ", want: true},
		{name: "term with wildcard", query: "* foo *", want: false},
		{name: "inline wildcard", query: "foo*bar", want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, isWildcardAllSearch(tc.query))
		})
	}
}

func TestSparsePatternTreatsWildcardOnlyAsMatchAll(t *testing.T) {
	t.Parallel()

	tests := []string{"*", "%", " * % * "}
	for _, query := range tests {
		query := query
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, "%", sparsePattern(query))
		})
	}
}

func TestSparseEventMatchClauseTreatsWildcardOnlyAsMatchAll(t *testing.T) {
	t.Parallel()

	tests := []string{"*", "%", " * % * "}
	for _, query := range tests {
		query := query
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, "true", sparseEventMatchClause(query))
			require.Equal(t, "0.1::real", sparseEventRankExpr(query))
		})
	}
}

func TestSparseEventArgsAvoidSkippedParameterForWildcardAll(t *testing.T) {
	t.Parallel()

	args, filter, limitParam := sparseEventArgs("*", Options{
		TopK: 50,
		Filters: &searchv1.SearchFilters{
			LocationIds: []string{"lab"},
			ThreatOnly:  true,
		},
	})

	require.Equal(t, 1, limitParam)
	require.Equal(t, []any{200, []string{"lab"}}, args)
	require.Contains(t, WhereSQL([]string{sparseEventMatchClause("*")}, filter.Clauses), "coalesce(se.location_id, '') = any($2::text[])")
	require.NotContains(t, sparseEventMatchClause("*"), "$1")
	require.NotContains(t, sparseEventRankExpr("*"), "$1")
}

func TestSparseSourceArgsAvoidRankingForWildcardAll(t *testing.T) {
	t.Parallel()

	opts := Options{
		TopK: 25,
		Filters: &searchv1.SearchFilters{
			LocationIds: []string{"lab"},
		},
	}
	args, filter, limitParam := sparseSourceArgs("*", opts, func(start int) SQLFilter {
		return BuildSourceFilters(opts.Filters, start, "d.mac_id", "d.location_id", "d.sensor_id", "d.last_seen")
	})

	matchClause := sparseSourceMatchClause("*", "lower(d.mac_id)")
	rankExpr := sparseSourceRankExpr("*", "lower(d.mac_id)")
	where := WhereSQL([]string{matchClause}, filter.Clauses)

	require.Equal(t, 1, limitParam)
	require.Equal(t, []any{100, []string{"lab"}}, args)
	require.Equal(t, "true", matchClause)
	require.Equal(t, "0.1::real", rankExpr)
	require.NotContains(t, where, "$1")
	require.Contains(t, where, "$2::text[]")
	require.NotContains(t, rankExpr, "similarity")
}

func TestSparseEventArgsKeepsQueryFirstForTextSearch(t *testing.T) {
	t.Parallel()

	args, filter, limitParam := sparseEventArgs("deauth", Options{
		TopK: 25,
		Filters: &searchv1.SearchFilters{
			LocationIds: []string{"lab"},
		},
	})

	require.Equal(t, 2, limitParam)
	require.Equal(t, []any{"deauth", 100, []string{"lab"}}, args)
	require.Contains(t, WhereSQL([]string{sparseEventMatchClause("deauth")}, filter.Clauses), "$1")
	require.Contains(t, WhereSQL([]string{sparseEventMatchClause("deauth")}, filter.Clauses), "$3::text[]")
}
