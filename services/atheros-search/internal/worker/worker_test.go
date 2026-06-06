package worker

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

func TestMakeJobChunksGroupsByKindAndSize(t *testing.T) {
	jobs := []db.EmbeddingJob{
		{JobID: 1, EmbeddingKind: "event"},
		{JobID: 2, EmbeddingKind: "device"},
		{JobID: 3, EmbeddingKind: "event"},
		{JobID: 4, EmbeddingKind: "event"},
	}

	chunks := makeJobChunks(jobs, 2)

	require.Len(t, chunks, 3)
	require.Equal(t, []int64{1, 3}, chunkIDs(chunks[0]))
	require.Equal(t, []int64{4}, chunkIDs(chunks[1]))
	require.Equal(t, []int64{2}, chunkIDs(chunks[2]))
}

func TestReachedMaxDrain(t *testing.T) {
	require.False(t, reachedMaxDrain(10, 0))
	require.False(t, reachedMaxDrain(1, 2))
	require.True(t, reachedMaxDrain(2, 2))
}

func TestEffectiveRequestBatchSizeRespectsMax(t *testing.T) {
	got := effectiveRequestBatchSize(config.Config{
		WorkerBatchSize:        64,
		WorkerRequestBatchSize: 200,
		WorkerRequestBatchMax:  128,
	})

	require.Equal(t, 128, got)
}

func TestShouldRunAlertSweep(t *testing.T) {
	require.False(t, shouldRunAlertSweep(9, 10))
	require.True(t, shouldRunAlertSweep(10, 10))
	require.True(t, shouldRunAlertSweep(10, 0))
}

func chunkIDs(jobs []db.EmbeddingJob) []int64 {
	out := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, job.JobID)
	}
	return out
}
