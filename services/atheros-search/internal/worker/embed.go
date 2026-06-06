package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/semaphore"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
)

type EmbeddedChunkResult struct {
	ChunkIndex            int
	Items                 []EmbeddedItem
	Failed                int
	PermanentFailed       int
	FailedByKind          map[string]int
	PermanentFailedByKind map[string]int
	PrepareMS             int64
	EmbedMS               int64
}

type EmbeddedItem struct {
	Prepared PreparedJob
	Vector   []float32
}

func EmbedChunk(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, embedder embed.Client, sem *semaphore.Weighted, chunk PrepareChunkResult) EmbeddedChunkResult {
	result := EmbeddedChunkResult{
		ChunkIndex:            chunk.ChunkIndex,
		Failed:                chunk.Failed,
		FailedByKind:          copyCounts(chunk.FailedByKind),
		PermanentFailedByKind: map[string]int{},
		PrepareMS:             chunk.PrepareMS,
	}
	if len(chunk.Prepared) == 0 {
		return result
	}

	if sem != nil {
		if err := sem.Acquire(ctx, 1); err != nil {
			failEmbeddedPrepared(ctx, pool, chunk.Prepared, err, false, &result)
			return result
		}
		defer sem.Release(1)
	}

	started := time.Now()
	kind := chunk.Prepared[0].Job.EmbeddingKind
	texts := make([]string, 0, len(chunk.Prepared))
	for _, item := range chunk.Prepared {
		texts = append(texts, item.Input.Text)
	}
	vectors, err := embedder.Embed(ctx, texts, embed.Kind(kind))
	result.EmbedMS = time.Since(started).Milliseconds()
	if err != nil {
		failEmbeddedPrepared(ctx, pool, chunk.Prepared, err, isPermanentEmbedError(err), &result)
		return result
	}
	if len(vectors) != len(chunk.Prepared) {
		err := fmt.Errorf("embedding backend returned %d vectors for %d jobs", len(vectors), len(chunk.Prepared))
		failEmbeddedPrepared(ctx, pool, chunk.Prepared, err, true, &result)
		return result
	}
	for i, vector := range vectors {
		prepared := chunk.Prepared[i]
		if len(vector) != cfg.EmbeddingDimensions {
			err := fmt.Errorf("embedding vector has %d dimensions, expected %d", len(vector), cfg.EmbeddingDimensions)
			failOneEmbedded(ctx, pool, prepared, err, true, &result)
			continue
		}
		result.Items = append(result.Items, EmbeddedItem{Prepared: prepared, Vector: vector})
	}
	return result
}

func failEmbeddedPrepared(ctx context.Context, pool *pgxpool.Pool, items []PreparedJob, err error, permanent bool, result *EmbeddedChunkResult) {
	for _, item := range items {
		failOneEmbedded(ctx, pool, item, err, permanent, result)
	}
}

func failOneEmbedded(ctx context.Context, pool *pgxpool.Pool, item PreparedJob, err error, permanent bool, result *EmbeddedChunkResult) {
	attempts := item.Job.Attempts
	if permanent {
		attempts = item.Job.MaxAttempts
		result.PermanentFailed++
		result.PermanentFailedByKind[item.Job.EmbeddingKind]++
	} else {
		result.Failed++
		result.FailedByKind[item.Job.EmbeddingKind]++
	}
	_ = db.FailJob(ctx, pool, item.Job.JobID, item.Job.LeaseToken, attempts, item.Job.MaxAttempts, err.Error())
}

func isPermanentEmbedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, embed.ErrCircuitOpen) {
		return false
	}
	message := err.Error()
	for code := http.StatusBadRequest; code < http.StatusInternalServerError; code++ {
		if code == http.StatusTooManyRequests {
			continue
		}
		if containsStatusCode(message, strconv.Itoa(code)) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(message), "dimension")
}

func containsStatusCode(message, code string) bool {
	start := 0
	for {
		idx := strings.Index(message[start:], code)
		if idx < 0 {
			return false
		}
		idx += start
		after := idx + len(code)
		if (idx == 0 || !isASCIIDigit(message[idx-1])) && (after == len(message) || !isASCIIDigit(message[after])) {
			return true
		}
		start = after
	}
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func copyCounts(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
