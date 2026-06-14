package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestSearchRejectsWildcardOnlyQuery(t *testing.T) {
	t.Parallel()

	svc := &Service{}

	_, err := svc.Search(context.Background(), &searchv1.SearchRequest{
		Query: "*",
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
