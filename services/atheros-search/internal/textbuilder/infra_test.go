package textbuilder

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestBuildEgoGraphInputSummarizesNeighbors(t *testing.T) {
	seen := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	rows := []InfrastructureGraphRow{
		{NodeA: "ap", NodeAType: "bssid", NodeB: "client-1", NodeBType: "client_mac", EdgeType: "association", LastSeen: pgtype.Timestamptz{Time: seen, Valid: true}},
		{NodeA: "ap", NodeAType: "bssid", NodeB: "corp", NodeBType: "ssid", EdgeType: "probe_target"},
		{NodeA: "vendor-x", NodeAType: "vendor", NodeB: "ap", NodeBType: "bssid", EdgeType: "vendor_seen"},
	}

	input := buildEgoGraphInput("ap", rows)

	require.Contains(t, input.Text, "center: ap")
	require.Contains(t, input.Text, "ssid: 1")
	require.Contains(t, input.Text, "clients: 1")
	require.Contains(t, input.Text, "vendor_diversity: 1")
	require.Contains(t, input.Text, "edges: association:1,probe_target:1,vendor_seen:1")
	require.Equal(t, &seen, input.SourceObservedAt)
	require.Equal(t, "ap", input.SourceMAC)
}
