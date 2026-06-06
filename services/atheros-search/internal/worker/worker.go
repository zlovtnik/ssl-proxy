package worker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/alerts"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/seqscore"
)

type Worker struct {
	Pool      *pgxpool.Pool
	AlertPool *pgxpool.Pool
	Embedder  embed.Client
	Config    config.Config
	Metrics   *metrics.Metrics
	Logger    zerolog.Logger
}

type RunOnceResult struct {
	Processed            int
	PermanentFailures    int
	RowsLeased           int
	DrainBatches         int
	DrainedToEmpty       bool
	MaxDrainBatchReached bool
	DrainMS              int64
	KindStats            map[string]KindRunStats
}

type KindRunStats struct {
	Leased          int
	Completed       int
	Failed          int
	PermanentFailed int
}

func (w *Worker) Start(ctx context.Context) error {
	poll := w.Config.WorkerPollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	iteration := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		iteration++
		if _, err := w.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.Logger.Warn().Err(err).Msg("worker drain iteration failed")
		}
		if iteration%10 == 0 {
			if released, err := db.ReleaseExpiredLeases(ctx, w.Pool); err == nil && released > 0 {
				w.Logger.Info().Int32("released", released).Msg("released expired embedding leases")
			} else if err != nil {
				w.Logger.Warn().Err(err).Msg("release expired embedding leases failed")
			}
		}
		if w.Config.AlertEnabled && shouldRunAlertSweep(iteration, w.Config.AlertSweepInterval) {
			w.startAlertSweep(ctx)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) (RunOnceResult, error) {
	started := time.Now()
	result := RunOnceResult{KindStats: map[string]KindRunStats{}}
	runStarted := time.Now()
	_ = db.MarkWorkerState(ctx, w.Pool, db.WorkerStateParams{
		WorkerName:       w.Config.WorkerName,
		Status:           "running",
		LastRunStartedAt: &runStarted,
	})

	for {
		if reachedMaxDrain(result.DrainBatches, w.Config.WorkerMaxDrainBatches) {
			result.MaxDrainBatchReached = true
			break
		}
		callCtx, cancel := context.WithTimeout(ctx, w.Config.WorkerDBCallTimeout)
		jobs, err := db.LeaseJobs(callCtx, w.Pool, w.Config.WorkerBatchSize, w.Config.WorkerName, w.Config.WorkerLeaseSeconds)
		cancel()
		if err != nil {
			return result, err
		}
		result.DrainBatches++
		result.RowsLeased += len(jobs)
		if len(jobs) == 0 {
			result.DrainedToEmpty = true
			break
		}
		for _, job := range jobs {
			stats := result.KindStats[job.EmbeddingKind]
			stats.Leased++
			result.KindStats[job.EmbeddingKind] = stats
			if w.Metrics != nil {
				w.Metrics.WorkerJobsLeased.WithLabelValues(job.EmbeddingKind).Inc()
			}
		}
		if w.Metrics != nil {
			w.Metrics.WorkerBatchSize.Observe(float64(len(jobs)))
		}
		process := w.processJobs(ctx, jobs)
		result.Processed += process.Completed
		result.PermanentFailures += process.PermanentFailed
		mergeKindStats(result.KindStats, process.KindStats)
	}

	finished := time.Now()
	result.DrainMS = time.Since(started).Milliseconds()
	_ = db.MarkWorkerState(ctx, w.Pool, db.WorkerStateParams{
		WorkerName:        w.Config.WorkerName,
		Status:            "idle",
		LastRunFinishedAt: &finished,
		RowsProcessed:     int64(result.Processed),
		LastRunStartedAt:  nil,
		LastCursor:        nil,
		LastError:         nil,
	})
	if w.Metrics != nil {
		if depth, err := db.CountWorkerQueueDepth(ctx, w.Pool); err == nil {
			w.Metrics.SetWorkerQueueDepth(depth)
		}
	}
	w.Logger.Info().
		Int("processed", result.Processed).
		Int("permanent_failures", result.PermanentFailures).
		Int("rows_leased", result.RowsLeased).
		Int("drain_batches", result.DrainBatches).
		Bool("drained_to_empty", result.DrainedToEmpty).
		Bool("max_drain_batch_reached", result.MaxDrainBatchReached).
		Int64("drain_ms", result.DrainMS).
		Msg("worker drain cycle finished")
	return result, nil
}

type processResult struct {
	Completed       int
	Failed          int
	PermanentFailed int
	KindStats       map[string]KindRunStats
}

func (w *Worker) processJobs(ctx context.Context, jobs []db.EmbeddingJob) processResult {
	chunks := makeJobChunks(jobs, effectiveRequestBatchSize(w.Config))
	prepCh := make(chan PrepareChunkResult, len(chunks))
	embedCh := make(chan EmbeddedChunkResult, len(chunks))
	completeCh := make(chan CompleteChunkResult, len(chunks))
	embedSem := semaphore.NewWeighted(int64(maxInt(w.Config.WorkerMaxConcurrentEmbed, 1)))

	var prepWG sync.WaitGroup
	for i, chunk := range chunks {
		prepWG.Add(1)
		go func(index int, chunk []db.EmbeddingJob) {
			defer prepWG.Done()
			prep := PrepareChunk(ctx, w.Config, w.Pool, index, chunk)
			if w.Metrics != nil {
				w.Metrics.WorkerPrepareLatency.Observe(float64(prep.PrepareMS))
			}
			prepCh <- prep
		}(i, chunk)
	}
	go func() {
		prepWG.Wait()
		close(prepCh)
	}()

	var embedWG sync.WaitGroup
	go func() {
		for prep := range prepCh {
			embedWG.Add(1)
			go func(prep PrepareChunkResult) {
				defer embedWG.Done()
				embedded := EmbedChunk(ctx, w.Config, w.Pool, w.Embedder, embedSem, prep)
				if w.Metrics != nil {
					w.Metrics.WorkerEmbedLatency.Observe(float64(embedded.EmbedMS))
				}
				embedCh <- embedded
			}(prep)
		}
		embedWG.Wait()
		close(embedCh)
	}()

	var completeWG sync.WaitGroup
	go func() {
		for embedded := range embedCh {
			completeWG.Add(1)
			go func(embedded EmbeddedChunkResult) {
				defer completeWG.Done()
				complete := CompleteChunk(ctx, w.Config, w.Pool, embedded)
				if w.Metrics != nil {
					w.Metrics.WorkerCompleteLatency.Observe(float64(complete.CompleteMS))
				}
				completeCh <- complete
			}(embedded)
		}
		completeWG.Wait()
		close(completeCh)
	}()

	result := processResult{KindStats: map[string]KindRunStats{}}
	for complete := range completeCh {
		result.Completed += complete.Succeeded
		result.Failed += complete.Failed
		result.PermanentFailed += complete.PermanentFailed
		for kind, count := range complete.SucceededByKind {
			stats := result.KindStats[kind]
			stats.Completed += count
			result.KindStats[kind] = stats
			if w.Metrics != nil {
				w.Metrics.WorkerJobsCompleted.WithLabelValues(kind).Add(float64(count))
			}
		}
		for kind, count := range complete.FailedByKind {
			stats := result.KindStats[kind]
			stats.Failed += count
			result.KindStats[kind] = stats
			if w.Metrics != nil {
				w.Metrics.WorkerJobsFailed.WithLabelValues(kind, "complete").Add(float64(count))
			}
		}
		for kind, count := range complete.PermanentFailedByKind {
			stats := result.KindStats[kind]
			stats.PermanentFailed += count
			result.KindStats[kind] = stats
			if w.Metrics != nil {
				w.Metrics.WorkerJobsPermanent.WithLabelValues(kind).Add(float64(count))
			}
		}
	}
	return result
}

func (w *Worker) startAlertSweep(ctx context.Context) {
	if w.AlertPool == nil {
		return
	}
	acquired, err := db.TryBeginAlertSweep(ctx, w.AlertPool)
	if err != nil {
		w.Logger.Warn().Err(err).Msg("alert sweep lock failed")
		return
	}
	if !acquired {
		return
	}
	go func() {
		defer func() {
			if err := db.FinishAlertSweep(context.Background(), w.AlertPool); err != nil {
				w.Logger.Warn().Err(err).Msg("alert sweep unlock failed")
			}
		}()
		scorer, err := seqscore.Load(ctx, w.AlertPool)
		if err != nil {
			w.Logger.Warn().Err(err).Msg("sequence scorer unavailable for alert sweep")
			scorer = seqscore.Empty()
		}
		cfg := alerts.ConfigFromSearchConfig(w.Config)
		if err := alerts.RunSweepWithMetrics(ctx, w.AlertPool, scorer, cfg, w.Logger, w.Metrics); err != nil {
			w.Logger.Warn().Err(err).Msg("alert sweep failed")
		}
	}()
}

func makeJobChunks(jobs []db.EmbeddingJob, size int) [][]db.EmbeddingJob {
	if size < 1 {
		size = 1
	}
	byKind := map[string][]db.EmbeddingJob{}
	kinds := []string{}
	for _, job := range jobs {
		if _, ok := byKind[job.EmbeddingKind]; !ok {
			kinds = append(kinds, job.EmbeddingKind)
		}
		byKind[job.EmbeddingKind] = append(byKind[job.EmbeddingKind], job)
	}
	chunks := [][]db.EmbeddingJob{}
	for _, kind := range kinds {
		group := byKind[kind]
		for len(group) > 0 {
			n := size
			if len(group) < n {
				n = len(group)
			}
			chunks = append(chunks, group[:n])
			group = group[n:]
		}
	}
	return chunks
}

func effectiveRequestBatchSize(cfg config.Config) int {
	size := cfg.WorkerRequestBatchSize
	if size <= 0 {
		size = cfg.WorkerBatchSize
	}
	if cfg.WorkerRequestBatchMax > 0 && size > cfg.WorkerRequestBatchMax {
		size = cfg.WorkerRequestBatchMax
	}
	if size <= 0 {
		size = 1
	}
	return size
}

func reachedMaxDrain(completedBatches, maxBatches int) bool {
	return maxBatches > 0 && completedBatches >= maxBatches
}

func shouldRunAlertSweep(iteration, interval int) bool {
	if interval <= 0 {
		interval = 10
	}
	return iteration > 0 && iteration%interval == 0
}

func mergeKindStats(dst map[string]KindRunStats, src map[string]KindRunStats) {
	for kind, item := range src {
		stats := dst[kind]
		stats.Completed += item.Completed
		stats.Failed += item.Failed
		stats.PermanentFailed += item.PermanentFailed
		dst[kind] = stats
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
