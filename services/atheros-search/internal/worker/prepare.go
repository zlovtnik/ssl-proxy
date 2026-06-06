package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/textbuilder"
)

type PreparedJob struct {
	Job           db.EmbeddingJob
	Input         db.EmbeddingInput
	ContentSHA256 string
}

type PrepareChunkResult struct {
	ChunkIndex   int
	Prepared     []PreparedJob
	Failed       int
	FailedByKind map[string]int
	PrepareMS    int64
}

func PrepareChunk(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, chunkIndex int, jobs []db.EmbeddingJob) PrepareChunkResult {
	started := time.Now()
	result := PrepareChunkResult{
		ChunkIndex:   chunkIndex,
		FailedByKind: map[string]int{},
	}
	inputs, err := textbuilder.BuildBatch(ctx, pool, jobs)
	if err != nil {
		for _, job := range jobs {
			failPreparedJob(ctx, pool, job, err)
			result.Failed++
			result.FailedByKind[job.EmbeddingKind]++
		}
		result.PrepareMS = time.Since(started).Milliseconds()
		return result
	}

	for _, job := range jobs {
		input, ok := inputs[job.SourceKey]
		if !ok {
			err := fmt.Errorf("%s source row not found: %s", job.EmbeddingKind, job.SourceKey)
			failPreparedJob(ctx, pool, job, err)
			result.Failed++
			result.FailedByKind[job.EmbeddingKind]++
			continue
		}
		input.Text = truncateInputText(input.Text, cfg.WorkerMaxInputTokens)
		hash := ""
		if job.ContentSHA256 != nil {
			hash = strings.TrimSpace(*job.ContentSHA256)
		}
		if hash == "" {
			hash = contentSHA256(input.Text)
		}
		result.Prepared = append(result.Prepared, PreparedJob{
			Job:           job,
			Input:         input,
			ContentSHA256: hash,
		})
	}
	result.PrepareMS = time.Since(started).Milliseconds()
	return result
}

func truncateInputText(text string, maxInputTokens int) string {
	maxChars := maxInputTokens * 3 / 2
	if maxChars <= 0 || len(text) <= maxChars {
		return text
	}
	cut := strings.LastIndex(text[:maxChars], "\n")
	if cut <= 0 {
		cut = maxChars
	}
	return text[:cut] + "\n[truncated]"
}

func contentSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func failPreparedJob(ctx context.Context, pool *pgxpool.Pool, job db.EmbeddingJob, err error) {
	_ = db.FailJob(ctx, pool, job.JobID, job.LeaseToken, job.Attempts, job.MaxAttempts, err.Error())
}
