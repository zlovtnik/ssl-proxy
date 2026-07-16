package worker

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"

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

func TestTransientBatchFailureDefersWithoutPerJobWrites(t *testing.T) {
	store := &fakeCompletionStore{
		batchFn: func(context.Context, []db.CompleteBatchRow) (int32, error) {
			return 0, &pgconn.PgError{Code: "57P03", Message: "database is starting"}
		},
	}
	var unavailable atomic.Int32
	result := completeChunkWithStore(
		context.Background(),
		completionTestConfig(),
		store,
		semaphore.NewWeighted(2),
		func(error) { unavailable.Add(1) },
		embeddedTestChunk(3),
	)

	require.Equal(t, 3, result.Deferred)
	require.Equal(t, 0, result.Failed)
	require.Equal(t, map[string]int{"event": 3}, result.DeferredByKind)
	require.Equal(t, deferredReasonDatabaseUnavailable, result.DeferredReason)
	require.True(t, isTransientDatabaseError(result.Err))
	require.Equal(t, int32(1), unavailable.Load())
	require.Equal(t, 1, store.batchCalls)
	require.Zero(t, store.idsCalls)
	require.Zero(t, store.oneCalls)
	require.Zero(t, store.failCalls)
}

func TestTransientCompletedIDsFailureSkipsFallbackWrites(t *testing.T) {
	store := &fakeCompletionStore{
		batchFn: func(context.Context, []db.CompleteBatchRow) (int32, error) {
			return 0, nil
		},
		idsFn: func(context.Context, []int64) (map[int64]struct{}, error) {
			return nil, io.EOF
		},
	}
	result := completeChunkWithStore(
		context.Background(),
		completionTestConfig(),
		store,
		semaphore.NewWeighted(2),
		nil,
		embeddedTestChunk(2),
	)

	require.Equal(t, 2, result.Deferred)
	require.Zero(t, store.oneCalls)
	require.Zero(t, store.failCalls)
}

func TestMidFallbackDatabaseOutageDoesNotFailJobs(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	store := &fakeCompletionStore{
		batchFn: func(context.Context, []db.CompleteBatchRow) (int32, error) {
			return 0, &pgconn.PgError{Code: "23505", Message: "force fallback"}
		},
		oneFn: func(context.Context, db.CompleteBatchRow) (bool, error) {
			return false, syscall.ECONNRESET
		},
	}
	result := completeChunkWithStore(
		ctx,
		completionTestConfig(),
		store,
		semaphore.NewWeighted(1),
		cancel,
		embeddedTestChunk(4),
	)

	require.Equal(t, 4, result.Deferred)
	require.Zero(t, result.Failed)
	require.Zero(t, store.failCalls)
	require.True(t, isTransientDatabaseError(result.Err))
	require.ErrorIs(t, context.Cause(ctx), syscall.ECONNRESET)
}

func TestNonTransientCompletionFailureUsesFailJob(t *testing.T) {
	constraint := &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	store := &fakeCompletionStore{
		batchFn: func(context.Context, []db.CompleteBatchRow) (int32, error) {
			return 0, constraint
		},
		oneFn: func(context.Context, db.CompleteBatchRow) (bool, error) {
			return false, constraint
		},
	}
	result := completeChunkWithStore(
		context.Background(),
		completionTestConfig(),
		store,
		semaphore.NewWeighted(1),
		nil,
		embeddedTestChunk(1),
	)

	require.False(t, isTransientDatabaseError(constraint))
	require.Equal(t, 1, result.Failed)
	require.Zero(t, result.Deferred)
	require.Equal(t, 1, store.failCalls)
}

func TestSharedCompletionSemaphoreBoundsGlobalDatabaseCalls(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	store := &fakeCompletionStore{
		batchFn: func(_ context.Context, rows []db.CompleteBatchRow) (int32, error) {
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			active.Add(-1)
			return int32(len(rows)), nil
		},
	}
	shared := semaphore.NewWeighted(2)
	var wg sync.WaitGroup
	results := make(chan CompleteChunkResult, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- completeChunkWithStore(
				context.Background(),
				completionTestConfig(),
				store,
				shared,
				nil,
				embeddedTestChunk(1),
			)
		}()
	}
	wg.Wait()
	close(results)
	for result := range results {
		require.Equal(t, 1, result.Succeeded)
	}

	require.LessOrEqual(t, maximum.Load(), int32(2))
	require.Equal(t, int32(2), maximum.Load())
}

func TestTransientDatabaseErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "connection class", err: &pgconn.PgError{Code: "08006"}},
		{name: "admin shutdown", err: &pgconn.PgError{Code: "57P01"}},
		{name: "crash shutdown", err: &pgconn.PgError{Code: "57P02"}},
		{name: "cannot connect now", err: &pgconn.PgError{Code: "57P03"}},
		{name: "resource exhaustion", err: &pgconn.PgError{Code: "53200"}},
		{name: "eof", err: io.EOF},
		{name: "unexpected eof", err: io.ErrUnexpectedEOF},
		{name: "reset", err: syscall.ECONNRESET},
		{name: "timeout", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.True(t, isTransientDatabaseError(fmt.Errorf("wrapped: %w", test.err)))
		})
	}
	require.False(t, isTransientDatabaseError(&pgconn.PgError{Code: "23505", Message: "unique violation"}))
}

func TestCompletionErrorSummaryIsBounded(t *testing.T) {
	errorsSeen := newBoundedErrors("completion persistence failures")
	for i := 0; i < 500; i++ {
		errorsSeen.Add(fmt.Errorf("job %d: %s", i, strings.Repeat("x", 1024)))
	}

	err := errorsSeen.Err()
	require.Error(t, err)
	require.Less(t, len(err.Error()), 600)
	require.Contains(t, err.Error(), "500 errors")
	require.NotContains(t, err.Error(), "job 499")
}

func completionTestConfig() config.Config {
	return config.Config{
		EmbeddingDimensions: 1,
		WorkerDBCallTimeout: 2 * time.Second,
	}
}

func embeddedTestChunk(count int) EmbeddedChunkResult {
	items := make([]EmbeddedItem, 0, count)
	for i := 0; i < count; i++ {
		lease := fmt.Sprintf("lease-%d", i+1)
		items = append(items, EmbeddedItem{
			Prepared: PreparedJob{
				Job: db.EmbeddingJob{
					JobID:          int64(i + 1),
					LeaseToken:     &lease,
					SourceTable:    "sync_events_expanded",
					SourceKey:      fmt.Sprintf("source-%d", i+1),
					EmbeddingModel: "model",
					EmbeddingKind:  "event",
					MaxAttempts:    3,
				},
				Input:         db.EmbeddingInput{Text: "event"},
				ContentSHA256: "hash",
			},
			Vector: []float32{0.1},
		})
	}
	return EmbeddedChunkResult{
		Items:                 items,
		FailedByKind:          map[string]int{},
		PermanentFailedByKind: map[string]int{},
	}
}

type fakeCompletionStore struct {
	mu         sync.Mutex
	batchFn    func(context.Context, []db.CompleteBatchRow) (int32, error)
	idsFn      func(context.Context, []int64) (map[int64]struct{}, error)
	oneFn      func(context.Context, db.CompleteBatchRow) (bool, error)
	failFn     func(context.Context, int64, *string, int32, int32, string) error
	batchCalls int
	idsCalls   int
	oneCalls   int
	failCalls  int
}

func (s *fakeCompletionStore) CompleteEmbeddingBatch(ctx context.Context, rows []db.CompleteBatchRow) (int32, error) {
	s.mu.Lock()
	s.batchCalls++
	fn := s.batchFn
	s.mu.Unlock()
	if fn == nil {
		return int32(len(rows)), nil
	}
	return fn(ctx, rows)
}

func (s *fakeCompletionStore) CompletedJobIDs(ctx context.Context, ids []int64) (map[int64]struct{}, error) {
	s.mu.Lock()
	s.idsCalls++
	fn := s.idsFn
	s.mu.Unlock()
	if fn == nil {
		return map[int64]struct{}{}, nil
	}
	return fn(ctx, ids)
}

func (s *fakeCompletionStore) CompleteOneEmbedding(ctx context.Context, row db.CompleteBatchRow) (bool, error) {
	s.mu.Lock()
	s.oneCalls++
	fn := s.oneFn
	s.mu.Unlock()
	if fn == nil {
		return true, nil
	}
	return fn(ctx, row)
}

func (s *fakeCompletionStore) FailJob(ctx context.Context, jobID int64, lease *string, attempts, maxAttempts int32, message string) error {
	s.mu.Lock()
	s.failCalls++
	fn := s.failFn
	s.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, jobID, lease, attempts, maxAttempts, message)
}

var _ completionStore = (*fakeCompletionStore)(nil)
