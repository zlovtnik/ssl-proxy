package worker

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/semaphore"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
)

type CompleteChunkResult struct {
	Succeeded             int
	Failed                int
	PermanentFailed       int
	SucceededByKind       map[string]int
	FailedByKind          map[string]int
	PermanentFailedByKind map[string]int
	CompleteMS            int64
}

func CompleteChunk(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, embedded EmbeddedChunkResult) CompleteChunkResult {
	started := time.Now()
	result := CompleteChunkResult{
		Failed:                embedded.Failed,
		PermanentFailed:       embedded.PermanentFailed,
		SucceededByKind:       map[string]int{},
		FailedByKind:          copyCounts(embedded.FailedByKind),
		PermanentFailedByKind: copyCounts(embedded.PermanentFailedByKind),
	}
	if len(embedded.Items) == 0 {
		return result
	}
	rows := make([]db.CompleteBatchRow, 0, len(embedded.Items))
	for _, item := range embedded.Items {
		rows = append(rows, completeBatchRow(cfg, item))
	}

	callCtx, cancel := context.WithTimeout(ctx, cfg.WorkerDBCallTimeout)
	completed, err := db.CompleteEmbeddingBatch(callCtx, pool, rows)
	cancel()
	if err == nil && int(completed) == len(rows) {
		for _, item := range embedded.Items {
			markCompleteSuccess(item, &result)
		}
		result.CompleteMS = time.Since(started).Milliseconds()
		return result
	}
	if err != nil && isDBPressureError(err) {
		markCompleteFailed(embedded.Items, &result)
		result.CompleteMS = time.Since(started).Milliseconds()
		return result
	}

	completedIDs := map[int64]struct{}{}
	if err == nil && int(completed) < len(rows) {
		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.JobID)
		}
		if got, idsErr := db.CompletedJobIDs(ctx, pool, ids); idsErr == nil {
			completedIDs = got
		}
	}

	limit := cfg.WorkerMaxConcurrentComplete
	if limit < 1 {
		limit = 1
	}
	sem := semaphore.NewWeighted(int64(limit))
	resultCh := make(chan completeOneResult, len(rows))
	for i, row := range rows {
		item := embedded.Items[i]
		if _, ok := completedIDs[row.JobID]; ok {
			markCompleteSuccess(item, &result)
			continue
		}
		if acquireErr := sem.Acquire(ctx, 1); acquireErr != nil {
			resultCh <- completeOneResult{item: item, err: acquireErr}
			continue
		}
		go func(row db.CompleteBatchRow, item EmbeddedItem) {
			defer sem.Release(1)
			callCtx, cancel := context.WithTimeout(ctx, cfg.WorkerDBCallTimeout)
			ok, oneErr := db.CompleteOneEmbedding(callCtx, pool, row)
			cancel()
			resultCh <- completeOneResult{item: item, ok: ok, err: oneErr}
		}(row, item)
	}

	pending := len(rows) - len(completedIDs)
	for i := 0; i < pending; i++ {
		one := <-resultCh
		if one.err == nil && one.ok {
			markCompleteSuccess(one.item, &result)
			continue
		}
		if one.err != nil {
			_ = db.FailJob(ctx, pool, one.item.Prepared.Job.JobID, one.item.Prepared.Job.LeaseToken, one.item.Prepared.Job.Attempts, one.item.Prepared.Job.MaxAttempts, one.err.Error())
		}
		result.Failed++
		result.FailedByKind[one.item.Prepared.Job.EmbeddingKind]++
	}
	result.CompleteMS = time.Since(started).Milliseconds()
	return result
}

type completeOneResult struct {
	item EmbeddedItem
	ok   bool
	err  error
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

func markCompleteFailed(items []EmbeddedItem, result *CompleteChunkResult) {
	for _, item := range items {
		result.Failed++
		result.FailedByKind[item.Prepared.Job.EmbeddingKind]++
	}
}

func isDBPressureError(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
