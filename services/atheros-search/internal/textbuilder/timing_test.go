package textbuilder

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestTimingProfileRowToInputBuildsFallback(t *testing.T) {
	start := time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC)
	row := TimingProfileRow{
		SourceMAC:              "aa",
		SensorID:               "sensor-a",
		WindowStart:            pgtype.Timestamptz{Time: start, Valid: true},
		TSFTP50US:              "10.2",
		BeaconIntervalMedianMS: "102.4",
	}

	input := timingProfileRowToInput(row)

	require.Contains(t, input.Text, "kind: timing_profile")
	require.Contains(t, input.Text, "hour_of_day: 13")
	require.Contains(t, input.Text, "tsft_p50_us: 10.2")
	require.Contains(t, input.Text, "beacon_interval_ms: 102.4")
	require.Equal(t, &start, input.SourceObservedAt)
	require.Equal(t, "sensor-a", input.SourceSensorID)
}

func TestTimingProfileRowToInputUsesPrebuiltText(t *testing.T) {
	row := TimingProfileRow{EmbeddingText: "kind: old\nwall_jitter_ms: 1.2"}

	input := timingProfileRowToInput(row)

	require.Equal(t, "kind: timing_profile\nwall_jitter_ms: 1.2", input.Text)
}

func TestTimingProfileRowToInputClampsPrebuiltText(t *testing.T) {
	row := TimingProfileRow{EmbeddingText: strings.Repeat("word ", wordBudget(ContentTokenBudget)+10)}

	input := timingProfileRowToInput(row)

	require.LessOrEqual(t, countWords(input.Text), wordBudget(ContentTokenBudget))
	require.Contains(t, input.Text, "...")
}
