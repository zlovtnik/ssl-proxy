package textbuilder

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestBehaviourRowToInputPrefersEmbeddingText(t *testing.T) {
	start := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Minute)
	row := BehaviourWindowRow{
		EmbeddingText: "kind: stale\nprotocol_mix: {\"dns\":2}",
		WindowStart:   pgtype.Timestamptz{Time: start, Valid: true},
		WindowEnd:     pgtype.Timestamptz{Time: end, Valid: true},
		EventCount:    30,
		SensorID:      "sensor-a",
		LocationID:    "lab",
		SourceMAC:     "aa:bb:cc:dd:ee:ff",
	}

	input := behaviourRowToInput(row)

	require.Contains(t, input.Text, "kind: behaviour_window")
	require.Contains(t, input.Text, "hour_of_day: 10")
	require.Contains(t, input.Text, "protocol_mix: {\"dns\":2}")
	require.Contains(t, input.Text, "events_per_minute: 15.0")
	require.NotContains(t, input.Text, "kind: stale")
	require.Equal(t, &start, input.SourceObservedAt)
	require.Equal(t, "sensor-a", input.SourceSensorID)
}

func TestBuildSnapshotFallbackUsesFields(t *testing.T) {
	start := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	row := BehaviourWindowRow{
		WindowStart:           pgtype.Timestamptz{Time: start, Valid: true},
		WindowEnd:             pgtype.Timestamptz{Time: end, Valid: true},
		EventCount:            12,
		ProtocolMix:           `{"dns":2,"http":1}`,
		FrameTypeDistribution: `{"management":3}`,
		SourceMAC:             "aa",
	}

	got := buildSnapshotFallback(row)

	require.Contains(t, got, "kind: behaviour_window")
	require.Contains(t, got, "source_mac: aa")
	require.Contains(t, got, `protocol_mix: {"dns":2,"http":1}`)
	require.Contains(t, got, "events_per_minute: 12.0")
}
