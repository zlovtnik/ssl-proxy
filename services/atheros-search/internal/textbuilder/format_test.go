package textbuilder

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAppendValueSkipsEmptySemanticValues(t *testing.T) {
	lines := []string{"kind: event"}

	AppendValue(&lines, "retry", "0")
	AppendValue(&lines, "frame_type", "management")
	AppendValue(&lines, "unknown", "unknown")

	require.Equal(t, []string{"kind: event", "frame_type: management"}, lines)
}

func TestNormalizeWPSNameStripsScreenSizeAndTVSuffix(t *testing.T) {
	require.Equal(t, "hisense", NormalizeWPSName(`60" Hisense Roku TV`))
	require.Equal(t, "living room", NormalizeWPSName("Living   Room Display"))
}

func TestTemporalContextLines(t *testing.T) {
	ts := time.Date(2026, 6, 5, 14, 0, 0, 0, time.UTC)

	require.Equal(t, []string{
		"hour_of_day: 14",
		"day_of_week: Friday",
		"is_weekend: false",
		"is_business_hours: true",
	}, TemporalContextLines(ts))
}

func TestClampTextPreservesLineBoundaries(t *testing.T) {
	got := ClampText("kind: event\none two three\nfour five", 4)

	require.Equal(t, "kind: event\none two...", got)
}

func TestTruncateTokenSequenceMarksDroppedTokens(t *testing.T) {
	got := TruncateTokenSequence("AUTH ASSOC_REQ EAPOL DATA", 2)

	require.Equal(t, "AUTH ASSOC_REQ (+2 truncated)", got)
}

func TestNormalizeJSONSortsMapKeys(t *testing.T) {
	got := NormalizeJSON(map[string]any{"b": 2, "a": 1})

	require.Equal(t, `{"a":1,"b":2}`, got)
}

func TestEventsPerMinute(t *testing.T) {
	start := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Minute)

	require.Equal(t, 7.5, EventsPerMinute(15, &start, &end))
	require.Zero(t, EventsPerMinute(15, &end, &start))
}
