package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/semaphore"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
)

const deferredReasonDatabaseUnavailable = "database_unavailable"

type CompleteChunkResult struct {
	ChunkIndex            int
	Succeeded             int
	Failed                int
	Deferred              int
	PermanentFailed       int
	SucceededByKind       map[string]int
	FailedByKind          map[string]int
	DeferredByKind        map[string]int
	PermanentFailedByKind map[string]int
	DeferredReason        string
	Err                   error
	PrepareMS             int64
	EmbedMS               int64
	CompleteMS            int64
}

type completionStore interface {
	CompleteEmbeddingBatch(context.Context, []db.CompleteBatchRow) (int32, error)
	CompletedJobIDs(context.Context, []int64) (map[int64]struct{}, error)
	CompleteOneEmbedding(context.Context, db.CompleteBatchRow) (bool, error)
	FailJob(context.Context, int64, *string, int32, int32, string) error
}

type postgresCompletionStore struct {
	pool *pgxpool.Pool
}

func (s postgresCompletionStore) CompleteEmbeddingBatch(ctx context.Context, rows []db.CompleteBatchRow) (int32, error) {
	return db.CompleteEmbeddingBatch(ctx, s.pool, rows)
}

func (s postgresCompletionStore) CompletedJobIDs(ctx context.Context, jobIDs []int64) (map[int64]struct{}, error) {
	return db.CompletedJobIDs(ctx, s.pool, jobIDs)
}

func (s postgresCompletionStore) CompleteOneEmbedding(ctx context.Context, row db.CompleteBatchRow) (bool, error) {
	return db.CompleteOneEmbedding(ctx, s.pool, row)
}

func (s postgresCompletionStore) FailJob(ctx context.Context, jobID int64, leaseToken *string, attempts, maxAttempts int32, message string) error {
	return db.FailJob(ctx, s.pool, jobID, leaseToken, attempts, maxAttempts, message)
}

func CompleteChunk(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	completeSem *semaphore.Weighted,
	onDatabaseUnavailable func(error),
	embedded EmbeddedChunkResult,
) CompleteChunkResult {
	return completeChunkWithStore(
		ctx,
		cfg,
		postgresCompletionStore{pool: pool},
		completeSem,
		onDatabaseUnavailable,
		embedded,
	)
}

func completeChunkWithStore(
	ctx context.Context,
	cfg config.Config,
	store completionStore,
	completeSem *semaphore.Weighted,
	onDatabaseUnavailable func(error),
	embedded EmbeddedChunkResult,
) (result CompleteChunkResult) {
	started := time.Now()
	errorsSeen := newBoundedErrors("completion persistence failures")
	result = CompleteChunkResult{
		ChunkIndex:            embedded.ChunkIndex,
		Failed:                embedded.Failed,
		Deferred:              embedded.Deferred,
		PermanentFailed:       embedded.PermanentFailed,
		SucceededByKind:       map[string]int{},
		FailedByKind:          copyCounts(embedded.FailedByKind),
		DeferredByKind:        copyCounts(embedded.DeferredByKind),
		PermanentFailedByKind: copyCounts(embedded.PermanentFailedByKind),
		DeferredReason:        embedded.DeferredReason,
		PrepareMS:             embedded.PrepareMS,
		EmbedMS:               embedded.EmbedMS,
	}
	defer func() {
		result.Err = errorsSeen.Err()
		result.CompleteMS = time.Since(started).Milliseconds()
	}()

	if embedded.Err != nil {
		errorsSeen.Add(embedded.Err)
		if isTransientDatabaseError(embedded.Err) {
			notifyDatabaseUnavailable(onDatabaseUnavailable, embedded.Err)
			markCompleteDeferred(embedded.Items, deferredReasonDatabaseUnavailable, &result)
			return result
		}
	}
	if len(embedded.Items) == 0 {
		return result
	}

	rows := make([]db.CompleteBatchRow, 0, len(embedded.Items))
	for _, item := range embedded.Items {
		rows = append(rows, completeBatchRow(cfg, item))
	}

	completed, err := withCompletionSlot(
		ctx,
		completeSem,
		cfg.WorkerDBCallTimeout,
		func(callCtx context.Context) (int32, error) {
			return store.CompleteEmbeddingBatch(callCtx, rows)
		},
	)
	if err == nil && int(completed) == len(rows) {
		for _, item := range embedded.Items {
			markCompleteSuccess(item, &result)
		}
		return result
	}
	if shouldDeferDatabaseOperation(ctx, err) {
		cause := databaseUnavailableCause(ctx, err)
		notifyDatabaseUnavailable(onDatabaseUnavailable, cause)
		markCompleteDeferred(embedded.Items, deferredReason(ctx, err), &result)
		errorsSeen.Add(firstNonNil(cause, err))
		return result
	}

	completedIDs := map[int64]struct{}{}
	if err == nil && int(completed) < len(rows) {
		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.JobID)
		}
		completedIDs, err = withCompletionSlot(
			ctx,
			completeSem,
			cfg.WorkerDBCallTimeout,
			func(callCtx context.Context) (map[int64]struct{}, error) {
				return store.CompletedJobIDs(callCtx, ids)
			},
		)
		if shouldDeferDatabaseOperation(ctx, err) {
			cause := databaseUnavailableCause(ctx, err)
			notifyDatabaseUnavailable(onDatabaseUnavailable, cause)
			markCompleteDeferred(embedded.Items, deferredReason(ctx, err), &result)
			errorsSeen.Add(firstNonNil(cause, err))
			return result
		}
		if err != nil {
			errorsSeen.Add(fmt.Errorf("query completed fallback job ids: %w", err))
			completedIDs = map[int64]struct{}{}
		}
	}

	resultCh := make(chan completeOneResult, len(rows))
	pending := 0
	for i, row := range rows {
		item := embedded.Items[i]
		if _, ok := completedIDs[row.JobID]; ok {
			markCompleteSuccess(item, &result)
			continue
		}
		pending++
		go func(row db.CompleteBatchRow, item EmbeddedItem) {
			resultCh <- completeOneWithFallback(
				ctx,
				cfg,
				store,
				completeSem,
				onDatabaseUnavailable,
				row,
				item,
			)
		}(row, item)
	}

	for i := 0; i < pending; i++ {
		one := <-resultCh
		switch {
		case one.ok:
			markCompleteSuccess(one.item, &result)
		case one.deferred:
			markCompleteDeferred([]EmbeddedItem{one.item}, one.deferredReason, &result)
			errorsSeen.Add(one.err)
		default:
			result.Failed++
			result.FailedByKind[one.item.Prepared.Job.EmbeddingKind]++
			errorsSeen.Add(one.err)
		}
	}
	return result
}

type completeOneResult struct {
	item           EmbeddedItem
	ok             bool
	deferred       bool
	deferredReason string
	err            error
}

func completeOneWithFallback(
	ctx context.Context,
	cfg config.Config,
	store completionStore,
	completeSem *semaphore.Weighted,
	onDatabaseUnavailable func(error),
	row db.CompleteBatchRow,
	item EmbeddedItem,
) completeOneResult {
	ok, err := withCompletionSlot(
		ctx,
		completeSem,
		cfg.WorkerDBCallTimeout,
		func(callCtx context.Context) (bool, error) {
			return store.CompleteOneEmbedding(callCtx, row)
		},
	)
	if err == nil {
		return completeOneResult{item: item, ok: ok}
	}
	if shouldDeferDatabaseOperation(ctx, err) {
		cause := databaseUnavailableCause(ctx, err)
		notifyDatabaseUnavailable(onDatabaseUnavailable, cause)
		return completeOneResult{
			item:           item,
			deferred:       true,
			deferredReason: deferredReason(ctx, err),
			err:            firstNonNil(cause, err),
		}
	}

	job := item.Prepared.Job
	failErr := withCompletionSlotError(
		ctx,
		completeSem,
		cfg.WorkerDBCallTimeout,
		func(callCtx context.Context) error {
			return store.FailJob(callCtx, job.JobID, job.LeaseToken, job.Attempts, job.MaxAttempts, err.Error())
		},
	)
	if shouldDeferDatabaseOperation(ctx, failErr) {
		cause := databaseUnavailableCause(ctx, failErr)
		notifyDatabaseUnavailable(onDatabaseUnavailable, cause)
		return completeOneResult{
			item:           item,
			deferred:       true,
			deferredReason: deferredReason(ctx, failErr),
			err:            firstNonNil(cause, failErr),
		}
	}
	if failErr != nil {
		return completeOneResult{item: item, err: fmt.Errorf("record completion failure: %w", failErr)}
	}
	return completeOneResult{item: item}
}

func withCompletionSlot[T any](
	ctx context.Context,
	sem *semaphore.Weighted,
	timeout time.Duration,
	call func(context.Context) (T, error),
) (T, error) {
	var zero T
	if sem != nil {
		if err := sem.Acquire(ctx, 1); err != nil {
			return zero, err
		}
		defer sem.Release(1)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return call(callCtx)
}

func withCompletionSlotError(
	ctx context.Context,
	sem *semaphore.Weighted,
	timeout time.Duration,
	call func(context.Context) error,
) error {
	_, err := withCompletionSlot(ctx, sem, timeout, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, call(callCtx)
	})
	return err
}

func completeBatchRow(cfg config.Config, item EmbeddedItem) db.CompleteBatchRow {
	job := item.Prepared.Job
	input := item.Prepared.Input
	return db.CompleteBatchRow{
		JobID:               job.JobID,
		LeaseToken:          job.LeaseToken,
		SourceTable:         job.SourceTable,
		SourceKey:           job.SourceKey,
		SourceObservedAt:    input.SourceObservedAt,
		SourceStreamName:    input.SourceStreamName,
		SourceSensorID:      input.SourceSensorID,
		SourceLocationID:    input.SourceLocationID,
		SourceMAC:           input.SourceMAC,
		EmbeddingModel:      job.EmbeddingModel,
		EmbeddingKind:       job.EmbeddingKind,
		EmbeddingDimensions: cfg.EmbeddingDimensions,
		ContentSHA256:       item.Prepared.ContentSHA256,
		ContentText:         input.Text,
		Embedding:           search.VectorLiteral(item.Vector),
		Metadata: map[string]any{
			"builder":        "atheros-search",
			"source_table":   job.SourceTable,
			"source_key":     job.SourceKey,
			"embedding_kind": job.EmbeddingKind,
		},
	}
}

func markCompleteSuccess(item EmbeddedItem, result *CompleteChunkResult) {
	result.Succeeded++
	result.SucceededByKind[item.Prepared.Job.EmbeddingKind]++
}

func markCompleteDeferred(items []EmbeddedItem, reason string, result *CompleteChunkResult) {
	if reason == "" {
		reason = deferredReasonDatabaseUnavailable
	}
	result.DeferredReason = reason
	for _, item := range items {
		result.Deferred++
		result.DeferredByKind[item.Prepared.Job.EmbeddingKind]++
	}
}

func notifyDatabaseUnavailable(callback func(error), err error) {
	if callback != nil && err != nil && isTransientDatabaseError(err) {
		callback(err)
	}
}

func firstNonNil(errors ...error) error {
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}
