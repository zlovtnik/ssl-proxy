package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestNewInitializesStableZeroValuedSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	NewForRegisterer(registry)

	families, err := registry.Gather()
	require.NoError(t, err)
	byName := make(map[string]int, len(families))
	for _, family := range families {
		byName[family.GetName()] = len(family.Metric)
	}
	require.Equal(t, 40, byName["athsearch_search_requests_total"])
	require.Equal(t, 20, byName["athsearch_search_latency_ms"])
	require.Equal(t, 5, byName["athsearch_results_returned_total"])
}
