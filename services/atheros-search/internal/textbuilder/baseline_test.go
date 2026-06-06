package textbuilder

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestBaselineRowsToInputSortsMetricsAndUsesLatestUpdatedAt(t *testing.T) {
	old := time.Date(2026, 6, 5, 11, 0, 0, 0, time.UTC)
	latest := old.Add(time.Hour)
	rows := []BaselineProfileRow{
		{BSSID: "aa", Metric: "z_metric", P50: "9", UpdatedAt: pgtype.Timestamptz{Time: old, Valid: true}},
		{BSSID: "aa", Metric: "a_metric", P5: "1", P50: "2", P95: "3", UpdatedAt: pgtype.Timestamptz{Time: latest, Valid: true}},
	}

	input := baselineRowsToInput(rows)

	require.Contains(t, input.Text, "kind: baseline_profile")
	require.Less(t, indexOf(input.Text, "metric: a_metric"), indexOf(input.Text, "metric: z_metric"))
	require.Equal(t, &latest, input.SourceObservedAt)
	require.Equal(t, "aa", input.SourceMAC)
}

func indexOf(s, needle string) int {
	for i := range s {
		if len(s[i:]) >= len(needle) && s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
