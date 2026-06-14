package search

import (
	"testing"

	"github.com/stretchr/testify/require"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestBuildWirelessFiltersUsesParameters(t *testing.T) {
	filter := BuildWirelessFilters(&searchv1.SearchFilters{
		LocationIds:       []string{"lab"},
		SourceMac:         "aa:bb:cc:dd:ee:ff",
		FrameSubtypes:     []string{"probe_request"},
		SecurityFlagsMask: 4,
		ThreatOnly:        true,
		Tags:              []string{"threat:test"},
	}, 3)
	sql := WhereSQL(nil, filter.Clauses)
	require.Contains(t, sql, "$3::text[]")
	require.Contains(t, sql, "$4")
	require.Contains(t, sql, "$5::text[]")
	require.Contains(t, sql, "$6")
	require.Contains(t, sql, "$7")
	require.NotContains(t, sql, "aa:bb:cc:dd:ee:ff")
	require.Len(t, filter.Args, 5)
}

func TestBuildWirelessFiltersCombinesSourceMacList(t *testing.T) {
	filter := BuildWirelessFilters(&searchv1.SearchFilters{
		SourceMac:  "AA:BB:CC:DD:EE:FF",
		SourceMacs: []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"},
	}, 1)
	sql := WhereSQL(nil, filter.Clauses)
	require.Contains(t, sql, "lower(se.source_mac) = any($1::text[])")
	require.Equal(t, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}, filter.Args[0])
}

func TestBuildSourceFiltersUsesParameters(t *testing.T) {
	filter := BuildSourceFilters(&searchv1.SearchFilters{
		LocationIds: []string{"lab"},
		SensorIds:   []string{"sensor-a"},
		SourceMac:   "aa:bb:cc:dd:ee:ff",
	}, 4, "b.source_mac", "b.location_id", "b.sensor_id", "b.window_start")
	sql := WhereSQL(nil, filter.Clauses)
	require.Contains(t, sql, "$4::text[]")
	require.Contains(t, sql, "$5::text[]")
	require.Contains(t, sql, "$6")
	require.NotContains(t, sql, "aa:bb:cc:dd:ee:ff")
	require.Len(t, filter.Args, 3)
}

func TestGraphFocusMACsDeduplicatesSourceAndExpandedMACs(t *testing.T) {
	got := graphFocusMACs(GraphFilters{
		SourceMAC: "AA:BB:CC:DD:EE:FF",
		focusMACs: []string{
			"aa:bb:cc:dd:ee:ff",
			"11:22:33:44:55:66",
		},
	})
	require.Equal(t, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}, got)
}
