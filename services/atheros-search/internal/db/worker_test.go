package db

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackoffSecondsMatchesRustClamp(t *testing.T) {
	require.Equal(t, int32(10), backoffSeconds(0))
	require.Equal(t, int32(10), backoffSeconds(1))
	require.Equal(t, int32(20), backoffSeconds(2))
	require.Equal(t, int32(50), backoffSeconds(5))
	require.Equal(t, int32(300), backoffSeconds(30))
	require.Equal(t, int32(300), backoffSeconds(100))
}

func TestCompleteBatchRowJSONPayload(t *testing.T) {
	lease := "lease-1"
	observed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	row := CompleteBatchRow{
		JobID:               42,
		LeaseToken:          &lease,
		SourceTable:         "sync_events_expanded",
		SourceKey:           "dedupe-1",
		SourceObservedAt:    &observed,
		SourceStreamName:    "wireless.audit",
		EmbeddingModel:      "nomic-embed-text-v2-moe",
		EmbeddingKind:       "event",
		EmbeddingDimensions: 768,
		ContentSHA256:       "abc123",
		ContentText:         "kind: event\nframe_type: management",
		Embedding:           "[0.1,0.2]",
		Metadata:            map[string]any{"builder": "atheros-search"},
	}

	payload, err := json.Marshal(row)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(payload, &got))
	require.Equal(t, float64(42), got["job_id"])
	require.Equal(t, "lease-1", got["lease_token"])
	require.Equal(t, "sync_events_expanded", got["source_table"])
	require.Equal(t, "dedupe-1", got["source_key"])
	require.Equal(t, "wireless.audit", got["source_stream_name"])
	require.Equal(t, "nomic-embed-text-v2-moe", got["embedding_model"])
	require.Equal(t, "event", got["embedding_kind"])
	require.Equal(t, float64(768), got["embedding_dimensions"])
	require.Equal(t, "abc123", got["content_sha256"])
	require.Equal(t, "kind: event\nframe_type: management", got["content_text"])
	require.Equal(t, "[0.1,0.2]", got["embedding"])
	require.NotContains(t, got, "source_sensor_id")
	require.NotContains(t, got, "source_location_id")
	require.NotContains(t, got, "source_mac")
	require.NotContains(t, got, "explanation_text")
}
