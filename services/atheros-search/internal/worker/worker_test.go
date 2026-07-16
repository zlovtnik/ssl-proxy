package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

func TestMakeJobChunksEventOnlyUsesRequestBatchSize(t *testing.T) {
	jobs := []db.EmbeddingJob{
		{JobID: 1, EmbeddingKind: "event"},
		{JobID: 2, EmbeddingKind: "event"},
		{JobID: 3, EmbeddingKind: "event"},
		{JobID: 4, EmbeddingKind: "event"},
		{JobID: 5, EmbeddingKind: "event"},
	}

	chunks := makeJobChunks(jobs, 2)

	require.Len(t, chunks, 3)
	require.Equal(t, []int64{1, 2}, chunkIDs(chunks[0]))
	require.Equal(t, []int64{3, 4}, chunkIDs(chunks[1]))
	require.Equal(t, []int64{5}, chunkIDs(chunks[2]))
	for _, chunk := range chunks {
		for _, job := range chunk {
			require.Equal(t, "event", job.EmbeddingKind)
		}
	}
}

func TestReachedMaxDrain(t *testing.T) {
	require.False(t, reachedMaxDrain(10, 0))
	require.False(t, reachedMaxDrain(1, 2))
	require.True(t, reachedMaxDrain(2, 2))
}

func TestShouldPollImmediately(t *testing.T) {
	backlogged := RunOnceResult{Processed: 1}
	capped := RunOnceResult{MaxDrainBatchReached: true}
	drained := RunOnceResult{DrainedToEmpty: true}

	require.True(t, shouldPollImmediately(backlogged, nil))
	require.True(t, shouldPollImmediately(capped, nil))
	require.False(t, shouldPollImmediately(drained, nil))
	require.False(t, shouldPollImmediately(capped, context.Canceled))
}

func TestEffectiveRequestBatchSizeRespectsMax(t *testing.T) {
	got := effectiveRequestBatchSize(config.Config{
		WorkerBatchSize:        64,
		WorkerRequestBatchSize: 200,
		WorkerRequestBatchMax:  128,
	})

	require.Equal(t, 128, got)
}

func TestStageWorkerCountBoundsConfiguredConcurrency(t *testing.T) {
	require.Equal(t, 0, stageWorkerCount(0, 4))
	require.Equal(t, 1, stageWorkerCount(5, 0))
	require.Equal(t, 3, stageWorkerCount(3, 8))
	require.Equal(t, 4, stageWorkerCount(10, 4))
}

func TestEffectiveStageWorkerCountsUseExistingKnobs(t *testing.T) {
	cfg := config.Config{
		WorkerMaxConcurrentEmbed:    3,
		WorkerMaxConcurrentComplete: 5,
	}

	require.Equal(t, 3, effectivePrepareWorkerCount(cfg))
	require.Equal(t, 3, effectiveEmbedWorkerCount(cfg))
	require.Equal(t, 3, effectiveBatchWorkerCount(cfg))
	require.Equal(t, 5, effectiveCompleteWorkerCount(cfg))
}

func TestDatabaseBackoffCapsAndResetsAfterSuccess(t *testing.T) {
	err := &pgconn.PgError{Code: "57P03", Message: "database is starting"}
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	state := 0
	for _, expected := range want {
		var delay time.Duration
		state, delay = databaseBackoffState(state, err)
		require.Equal(t, expected, delay)
	}

	state, delay := databaseBackoffState(state, nil)
	require.Zero(t, state)
	require.Zero(t, delay)
	state, delay = databaseBackoffState(state, err)
	require.Equal(t, 1, state)
	require.Equal(t, time.Second, delay)
}

func TestLeaseBatchesStopsAfterSharedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	called := make(chan struct{})
	var calls atomic.Int32
	w := Worker{
		Config: config.Config{
			WorkerBatchSize:     4,
			WorkerDBCallTimeout: time.Second,
		},
		leaseJobs: func(context.Context, int, string, int) ([]db.EmbeddingJob, error) {
			calls.Add(1)
			close(called)
			return []db.EmbeddingJob{{JobID: 1, EmbeddingKind: "event"}}, nil
		},
	}
	batchCh := make(chan []db.EmbeddingJob)
	done := make(chan leaseRunSummary, 1)
	go func() {
		done <- w.leaseBatches(ctx, batchCh)
	}()

	<-called
	databaseErr := &pgconn.PgError{Code: "57P03", Message: "database is starting"}
	cancel(databaseErr)
	summary := <-done

	require.Equal(t, int32(1), calls.Load())
	require.True(t, isTransientDatabaseError(summary.Err))
	require.Equal(t, 1, summary.RowsLeased)
}

func TestSendWithContextReturnsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.False(t, sendWithContext(ctx, make(chan int), 1))
}

func TestShouldRunAlertSweep(t *testing.T) {
	require.False(t, shouldRunAlertSweep(9, 10))
	require.True(t, shouldRunAlertSweep(10, 10))
	require.True(t, shouldRunAlertSweep(10, 0))
}

func TestFinishedWorkerStatus(t *testing.T) {
	require.Equal(t, "idle", finishedWorkerStatus(nil))
	require.Equal(t, "idle", finishedWorkerStatus(context.Canceled))
	require.Equal(t, "failed", finishedWorkerStatus(errors.New("database unavailable")))
}

func chunkIDs(jobs []db.EmbeddingJob) []int64 {
	out := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, job.JobID)
	}
	return out
}
