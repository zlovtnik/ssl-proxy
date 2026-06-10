package worker

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

func TestCompleteBatchRowUsesVectorLiteralAndMetadata(t *testing.T) {
	lease := "lease"
	observed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	row := completeBatchRow(config.Config{EmbeddingDimensions: 3}, EmbeddedItem{
		Prepared: PreparedJob{
			Job: db.EmbeddingJob{
				JobID:          7,
				LeaseToken:     &lease,
				SourceTable:    "sync_events_expanded",
				SourceKey:      "dedupe",
				EmbeddingModel: "model",
				EmbeddingKind:  "event",
			},
			Input: db.EmbeddingInput{
				Text:             "kind: event",
				SourceObservedAt: &observed,
				SourceStreamName: "wireless.audit",
				SourceMAC:        "aa",
			},
			ContentSHA256: "hash",
		},
		Vector: []float32{0.1, 0.2, 0.3},
	})

	require.Equal(t, int64(7), row.JobID)
	require.Equal(t, "[0.1,0.2,0.3]", row.Embedding)
	require.Equal(t, 3, row.EmbeddingDimensions)
	require.Equal(t, "atheros-search", row.Metadata["builder"])
	require.Equal(t, &observed, row.SourceObservedAt)
}

func TestIsDBPressureError(t *testing.T) {
	require.True(t, isDBPressureError(pgx.ErrNoRows))
	require.True(t, isDBPressureError(context.DeadlineExceeded))
	require.True(t, isDBPressureError(context.Canceled))
}
