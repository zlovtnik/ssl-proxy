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
	leaseJobs func(context.Context, int, string, int) ([]db.EmbeddingJob, error)
}

type RunOnceResult struct {
	Processed            int
	Deferred             int
	PermanentFailures    int
	RowsLeased           int
	DrainBatches         int
	DrainedToEmpty       bool
	MaxDrainBatchReached bool
	DrainMS              int64
	PrepareMS            int64
	EmbedMS              int64
	CompleteMS           int64
	ChunksPrepared       int
	ChunksEmbedded       int
	ChunksCompleted      int
	KindStats            map[string]KindRunStats
}

type KindRunStats struct {
	Leased          int
	Completed       int
	Failed          int
	Deferred        int
	PermanentFailed int
}

func (w *Worker) Start(ctx context.Context) error {
	poll := w.Config.WorkerPollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	iteration := 0
	transientFailures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		iteration++
		result, err := w.RunOnce(ctx)
		databaseUnavailable := isTransientDatabaseError(err)
		retryDelay := time.Duration(0)
		transientFailures, retryDelay = databaseBackoffState(transientFailures, err)
		if err != nil && !errors.Is(err, context.Canceled) {
			event := w.Logger.Warn().Err(err)
			if databaseUnavailable {
				event = event.
					Int("transient_db_failures", transientFailures).
					Dur("retry_after", retryDelay)
			}
			event.Msg("worker drain iteration failed")
		}

		if !databaseUnavailable && iteration%10 == 0 {
			if released, err := db.ReleaseExpiredLeases(ctx, w.Pool); err == nil && released > 0 {
				w.Logger.Info().Int32("released", released).Msg("released expired embedding leases")
			} else if err != nil {
				w.Logger.Warn().Err(err).Msg("release expired embedding leases failed")
			}
		}
		if w.Config.AlertEnabled && shouldRunAlertSweep(iteration, w.Config.AlertSweepInterval) {
			w.startAlertSweep(ctx)
		}

		// Only ticker-sleep when the queue was genuinely drained. Under
		// sustained load, immediately start the next drain cycle.
		if shouldPollImmediately(result, err) {
			w.Logger.Debug().
				Int("processed", result.Processed).
				Int("drain_batches", result.DrainBatches).
				Msg("backlog detected; polling immediately")
			continue
		}

		wait := poll
		if databaseUnavailable {
			wait = retryDelay
		}
		if err := waitForContext(ctx, wait); err != nil {
			return err
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) (RunOnceResult, error) {
	started := time.Now()
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	result := RunOnceResult{KindStats: map[string]KindRunStats{}}
	runStarted := time.Now()
	_ = db.MarkWorkerState(ctx, w.Pool, db.WorkerStateParams{
		WorkerName:       w.Config.WorkerName,
		Status:           "running",
		LastRunStartedAt: &runStarted,
	})

	batchWorkers := effectiveBatchWorkerCount(w.Config)
	batchCh := make(chan []db.EmbeddingJob, batchWorkers)
	processCh := make(chan processResult, batchWorkers)
	leaseSummaryCh := make(chan leaseRunSummary, 1)
	embedSem := semaphore.NewWeighted(int64(effectiveEmbedWorkerCount(w.Config)))
	completeSem := semaphore.NewWeighted(int64(effectiveCompleteWorkerCount(w.Config)))

	go func() {
		leaseSummaryCh <- w.leaseBatches(runCtx, batchCh)
	}()

	var processWG sync.WaitGroup
	for i := 0; i < batchWorkers; i++ {
		processWG.Add(1)
		go func() {
			defer processWG.Done()
			for jobs := range batchCh {
				process := w.processJobs(runCtx, jobs, embedSem, completeSem, cancelRun)
				processCh <- process
			}
		}()
	}
	go func() {
		processWG.Wait()
		close(processCh)
	}()

	runErrors := newBoundedErrors("worker drain failures")
	for process := range processCh {
		runErrors.Add(process.Err)
		result.Processed += process.Completed
		result.Deferred += process.Deferred
		result.PermanentFailures += process.PermanentFailed
		result.PrepareMS += process.PrepareMS
		result.EmbedMS += process.EmbedMS
		result.CompleteMS += process.CompleteMS
		result.ChunksPrepared += process.ChunksPrepared
		result.ChunksEmbedded += process.ChunksEmbedded
		result.ChunksCompleted += process.ChunksCompleted
		mergeKindStats(result.KindStats, process.KindStats)
	}

	leaseSummary := <-leaseSummaryCh
	result.RowsLeased = leaseSummary.RowsLeased
	result.DrainBatches = leaseSummary.DrainBatches
	result.DrainedToEmpty = leaseSummary.DrainedToEmpty
	result.MaxDrainBatchReached = leaseSummary.MaxDrainBatchReached
	mergeKindStats(result.KindStats, leaseSummary.KindStats)
	runErrors.Add(leaseSummary.Err)
	if cause := context.Cause(runCtx); cause != nil {
		runErrors.Add(cause)
	}

	finished := time.Now()
	runErr := runErrors.Err()
	var lastErr *string
	if runErr != nil {
		msg := runErr.Error()
		lastErr = &msg
	}
	timeout := w.Config.WorkerDBCallTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	stateCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result.DrainMS = time.Since(started).Milliseconds()
	_ = db.MarkWorkerState(stateCtx, w.Pool, db.WorkerStateParams{
		WorkerName:        w.Config.WorkerName,
		Status:            finishedWorkerStatus(runErr),
		LastRunFinishedAt: &finished,
		RowsProcessed:     int64(result.Processed),
		LastRunStartedAt:  nil,
		LastCursor:        nil,
		LastError:         lastErr,
	})
	if w.Metrics != nil && !isTransientDatabaseError(runErr) {
		if depth, err := db.CountWorkerQueueDepth(ctx, w.Pool); err == nil {
			w.Metrics.SetWorkerQueueDepth(depth)
		}
	}
	w.Logger.Info().
		Int("processed", result.Processed).
		Int("deferred", result.Deferred).
		Int("permanent_failures", result.PermanentFailures).
		Int("rows_leased", result.RowsLeased).
		Int("drain_batches", result.DrainBatches).
		Bool("drained_to_empty", result.DrainedToEmpty).
		Bool("max_drain_batch_reached", result.MaxDrainBatchReached).
		Int64("drain_ms", result.DrainMS).
		Int64("prepare_ms", result.PrepareMS).
		Int64("embed_ms", result.EmbedMS).
		Int64("complete_ms", result.CompleteMS).
		Int("chunks_prepared", result.ChunksPrepared).
		Int("chunks_embedded", result.ChunksEmbedded).
		Int("chunks_completed", result.ChunksCompleted).
		Interface("kind_stats", result.KindStats).
		Msg("worker drain cycle finished")
	return result, runErr
}

type processResult struct {
	Completed       int
	Failed          int
	Deferred        int
	PermanentFailed int
	Err             error
	PrepareMS       int64
	EmbedMS         int64
	CompleteMS      int64
	ChunksPrepared  int
	ChunksEmbedded  int
	ChunksCompleted int
	KindStats       map[string]KindRunStats
}

type leaseRunSummary struct {
	RowsLeased           int
	DrainBatches         int
	DrainedToEmpty       bool
	MaxDrainBatchReached bool
	KindStats            map[string]KindRunStats
	Err                  error
}

type indexedJobChunk struct {
	Index int
	Jobs  []db.EmbeddingJob
}

func (w *Worker) leaseBatches(ctx context.Context, batchCh chan<- []db.EmbeddingJob) leaseRunSummary {
	defer close(batchCh)
	summary := leaseRunSummary{KindStats: map[string]KindRunStats{}}
	for {
		if cause := context.Cause(ctx); cause != nil {
			summary.Err = cause
			return summary
		}
		if reachedMaxDrain(summary.DrainBatches, w.Config.WorkerMaxDrainBatches) {
			summary.MaxDrainBatchReached = true
			return summary
		}
		timeout := w.Config.WorkerDBCallTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		jobs, err := w.callLeaseJobs(callCtx)
		cancel()
		if err != nil {
			summary.Err = err
			return summary
		}
		summary.DrainBatches++
		summary.RowsLeased += len(jobs)
		if len(jobs) == 0 {
			summary.DrainedToEmpty = true
			return summary
		}
		for _, job := range jobs {
			stats := summary.KindStats[job.EmbeddingKind]
			stats.Leased++
			summary.KindStats[job.EmbeddingKind] = stats
			if w.Metrics != nil {
				w.Metrics.WorkerJobsLeased.WithLabelValues(job.EmbeddingKind).Inc()
			}
		}
		if w.Metrics != nil {
			w.Metrics.WorkerBatchSize.Observe(float64(len(jobs)))
		}
		if !sendWithContext(ctx, batchCh, jobs) {
			summary.Err = context.Cause(ctx)
			return summary
		}
	}
}

func (w *Worker) callLeaseJobs(ctx context.Context) ([]db.EmbeddingJob, error) {
	if w.leaseJobs != nil {
		return w.leaseJobs(ctx, w.Config.WorkerBatchSize, w.Config.WorkerName, w.Config.WorkerLeaseSeconds)
	}
	return db.LeaseJobs(ctx, w.Pool, w.Config.WorkerBatchSize, w.Config.WorkerName, w.Config.WorkerLeaseSeconds)
}

func (w *Worker) processJobs(
	ctx context.Context,
	jobs []db.EmbeddingJob,
	embedSem *semaphore.Weighted,
	completeSem *semaphore.Weighted,
	onDatabaseUnavailable func(error),
) processResult {
	chunks := makeJobChunks(jobs, effectiveRequestBatchSize(w.Config))
	result := processResult{KindStats: map[string]KindRunStats{}}
	if len(chunks) == 0 {
		return result
	}

	chunkCh := make(chan indexedJobChunk)
	prepCh := make(chan PrepareChunkResult, stageWorkerCount(len(chunks), effectivePrepareWorkerCount(w.Config)))
	embedCh := make(chan EmbeddedChunkResult, stageWorkerCount(len(chunks), effectiveEmbedWorkerCount(w.Config)))
	completeCh := make(chan CompleteChunkResult, len(chunks))
	completionErrors := newBoundedErrors("completion stage failures")

	var prepWG sync.WaitGroup
	for i := 0; i < stageWorkerCount(len(chunks), effectivePrepareWorkerCount(w.Config)); i++ {
		prepWG.Add(1)
		go func() {
			defer prepWG.Done()
			for chunk := range chunkCh {
				prep := PrepareChunk(ctx, w.Config, w.Pool, chunk.Index, chunk.Jobs)
				if w.Metrics != nil {
					w.Metrics.WorkerPrepareLatency.Observe(float64(prep.PrepareMS))
				}
				if !sendWithContext(ctx, prepCh, prep) {
					return
				}
			}
		}()
	}
	go func() {
		defer close(chunkCh)
		for i, chunk := range chunks {
			if !sendWithContext(ctx, chunkCh, indexedJobChunk{Index: i, Jobs: chunk}) {
				return
			}
		}
	}()
	go func() {
		prepWG.Wait()
		close(prepCh)
	}()

	var embedWG sync.WaitGroup
	for i := 0; i < stageWorkerCount(len(chunks), effectiveEmbedWorkerCount(w.Config)); i++ {
		embedWG.Add(1)
		go func() {
			defer embedWG.Done()
			for prep := range prepCh {
				embedded := EmbedChunk(ctx, w.Config, w.Pool, w.Embedder, embedSem, prep)
				if w.Metrics != nil {
					w.Metrics.WorkerEmbedLatency.Observe(float64(embedded.EmbedMS))
				}
				if !sendWithContext(ctx, embedCh, embedded) {
					return
				}
			}
		}()
	}
	go func() {
		embedWG.Wait()
		close(embedCh)
	}()

	var completeWG sync.WaitGroup
	for i := 0; i < stageWorkerCount(len(chunks), effectiveCompleteWorkerCount(w.Config)); i++ {
		completeWG.Add(1)
		go func() {
			defer completeWG.Done()
			for embedded := range embedCh {
				complete := CompleteChunk(ctx, w.Config, w.Pool, completeSem, onDatabaseUnavailable, embedded)
				if w.Metrics != nil {
					w.Metrics.WorkerCompleteLatency.Observe(float64(complete.CompleteMS))
				}
				completeCh <- complete
			}
		}()
	}
	go func() {
		completeWG.Wait()
		close(completeCh)
	}()

	for complete := range completeCh {
		completionErrors.Add(complete.Err)
		result.Completed += complete.Succeeded
		result.Failed += complete.Failed
		result.Deferred += complete.Deferred
		result.PermanentFailed += complete.PermanentFailed
		result.PrepareMS += complete.PrepareMS
		result.EmbedMS += complete.EmbedMS
		result.CompleteMS += complete.CompleteMS
		result.ChunksPrepared++
		result.ChunksEmbedded++
		result.ChunksCompleted++
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
		for kind, count := range complete.DeferredByKind {
			stats := result.KindStats[kind]
			stats.Deferred += count
			result.KindStats[kind] = stats
			if w.Metrics != nil {
				reason := complete.DeferredReason
				if reason == "" {
					reason = deferredReasonDatabaseUnavailable
				}
				w.Metrics.WorkerJobsDeferred.WithLabelValues(kind, reason).Add(float64(count))
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
	result.Err = completionErrors.Err()
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
	if len(jobs) == 0 {
		return nil
	}
	firstKind := jobs[0].EmbeddingKind
	sameKind := true
	for _, job := range jobs[1:] {
		if job.EmbeddingKind != firstKind {
			sameKind = false
			break
		}
	}
	if sameKind {
		return splitJobGroup(jobs, size)
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

func splitJobGroup(group []db.EmbeddingJob, size int) [][]db.EmbeddingJob {
	chunks := [][]db.EmbeddingJob{}
	for len(group) > 0 {
		n := size
		if len(group) < n {
			n = len(group)
		}
		chunks = append(chunks, group[:n])
		group = group[n:]
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

func effectivePrepareWorkerCount(cfg config.Config) int {
	return maxInt(cfg.WorkerMaxConcurrentEmbed, 1)
}

func effectiveEmbedWorkerCount(cfg config.Config) int {
	return maxInt(cfg.WorkerMaxConcurrentEmbed, 1)
}

func effectiveCompleteWorkerCount(cfg config.Config) int {
	return maxInt(cfg.WorkerMaxConcurrentComplete, 1)
}

func effectiveBatchWorkerCount(cfg config.Config) int {
	return maxInt(cfg.WorkerMaxConcurrentEmbed, 1)
}

func stageWorkerCount(workItems, configured int) int {
	if workItems <= 0 {
		return 0
	}
	if configured < 1 {
		configured = 1
	}
	if configured > workItems {
		return workItems
	}
	return configured
}

func sendWithContext[T any](ctx context.Context, ch chan<- T, value T) bool {
	select {
	case ch <- value:
		return true
	case <-ctx.Done():
		return false
	}
}

func reachedMaxDrain(completedBatches, maxBatches int) bool {
	return maxBatches > 0 && completedBatches >= maxBatches
}

func shouldPollImmediately(result RunOnceResult, err error) bool {
	return err == nil && !result.DrainedToEmpty
}

func databaseBackoffState(previousFailures int, err error) (int, time.Duration) {
	if !isTransientDatabaseError(err) {
		return 0, 0
	}
	failures := previousFailures + 1
	return failures, transientDatabaseBackoff(failures)
}

func transientDatabaseBackoff(failures int) time.Duration {
	delays := [...]time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
	}
	if failures <= 1 {
		return delays[0]
	}
	if failures >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[failures-1]
}

func waitForContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func shouldRunAlertSweep(iteration, interval int) bool {
	if interval <= 0 {
		interval = 10
	}
	return iteration > 0 && iteration%interval == 0
}

func finishedWorkerStatus(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return "idle"
	}
	return "failed"
}

func mergeKindStats(dst map[string]KindRunStats, src map[string]KindRunStats) {
	for kind, item := range src {
		stats := dst[kind]
		stats.Leased += item.Leased
		stats.Completed += item.Completed
		stats.Failed += item.Failed
		stats.Deferred += item.Deferred
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
