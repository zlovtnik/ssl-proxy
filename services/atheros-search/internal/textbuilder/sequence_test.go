package textbuilder

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestFrameSequenceRowToInputInsertsLogProbBeforeFrameCount(t *testing.T) {
	start := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	end := start.Add(30 * time.Second)
	score := -2.5
	row := FrameSequenceRow{
		SourceMAC:        "aa",
		SensorID:         "sensor-a",
		LocationID:       "lab",
		WindowStart:      pgtype.Timestamptz{Time: start, Valid: true},
		WindowEnd:        pgtype.Timestamptz{Time: end, Valid: true},
		SequenceTokens:   "AUTH ASSOC_REQ EAPOL",
		SemanticTokens:   "AUTH ASSOC_REQ",
		FrameCount:       3,
		PrecomputedScore: &score,
	}

	input := frameSequenceRowToInput(row)

	require.Equal(t, &start, input.SourceObservedAt)
	require.Contains(t, input.Text, "tokens: AUTH ASSOC_REQ")
	require.Contains(t, input.Text, "window_secs: 30")
	require.Less(t, strings.Index(input.Text, "log_prob:"), strings.Index(input.Text, "frame_count:"))
	require.Contains(t, input.Text, "log_prob: -2.500000")
}
