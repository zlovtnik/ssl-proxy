package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestNewCompletionRowBuildsVecWorkerPayload(t *testing.T) {
	observed := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	job := embeddingJob{
		JobID:          42,
		SourceTable:    "sync_events",
		SourceKey:      "dedupe-1",
		EmbeddingModel: "nomic-embed-text-v2-moe",
		EmbeddingKind:  "event",
		LeaseToken:     "lease-1",
	}
	input := embeddingInput{
		Text:             "kind: event\nframe_type: management",
		SourceObservedAt: &observed,
		SourceStreamName: "wireless.audit",
		SourceSensorID:   "sensor-a",
		SourceLocationID: "lab",
		SourceMAC:        "aa:bb:cc:dd:ee:ff",
		Metadata:         baseMetadata(job),
	}

	row := newCompletionRow(job, input, []float32{0.1, 0.2, 0.3}, 768)

	sum := sha256.Sum256([]byte(input.Text))
	require.Equal(t, int64(42), row.JobID)
	require.Equal(t, "lease-1", row.LeaseToken)
	require.Equal(t, hex.EncodeToString(sum[:]), row.ContentSHA256)
	require.Equal(t, "[0.1,0.2,0.3]", row.Embedding)
	require.Equal(t, "atheros-search", row.Metadata["builder"])
	require.Equal(t, &observed, row.SourceObservedAt)
}

func TestPrebuiltKindTextStripsExistingKindAndAddsTemporalContext(t *testing.T) {
	observed := time.Date(2026, 6, 6, 22, 0, 0, 0, time.UTC)

	got := prebuiltKindText("behaviour_window", "kind: stale\nprotocol_mix: {\"dns\":2}", &observed)

	require.Equal(t, "kind: behaviour_window\nhour_of_day: 22\nday_of_week: saturday\nis_weekend: true\nis_business_hours: false\nprotocol_mix: {\"dns\":2}", got)
}

func TestTruncateWordsMarksDroppedTokens(t *testing.T) {
	got := truncateWords("one two three four", 2)

	require.Equal(t, "one two (+2 truncated)", got)
}

func TestTruncateErrorPreservesUTF8(t *testing.T) {
	got := truncateError(errors.New(strings.Repeat("a", 2047) + "é"))

	require.True(t, utf8.ValidString(got))
	require.Len(t, got, 2047)
}
