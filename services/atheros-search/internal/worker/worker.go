package worker

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Pool struct {
	db       *sql.DB
	logger   zerolog.Logger
	cfg      PoolConfig
	embedder Embedder
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type PoolConfig struct {
	WorkerCount       int
	LeaseSeconds      int
	PollInterval      time.Duration
	BatchSize         int
	WorkerID          string
	HealthPollEnabled bool
}

type Embedder interface {
	Embed(ctx context.Context, texts []string, kind string) ([][]float32, error)
}

type Job struct {
	JobID          string
	DocumentID     string
	EmbeddingKind  string
	EmbeddingModel string
	ContentSHA256  string
	NormalizedText string
	Priority       int
	LeaseToken     string
	LeaseFence     int64
}

func NewPool(db *sql.DB, embedder Embedder, cfg PoolConfig, logger zerolog.Logger) *Pool {
	if cfg.WorkerCount < 1 {
		cfg.WorkerCount = 1
	}
	if cfg.LeaseSeconds < 1 {
		cfg.LeaseSeconds = 1800
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 64
	}
	return &Pool{
		db:       db,
		logger:   logger.With().Str("component", "worker-pool").Logger(),
		cfg:      cfg,
		embedder: embedder,
	}
}

func (p *Pool) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	for i := 0; i < p.cfg.WorkerCount; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx, i)
	}
	if p.cfg.HealthPollEnabled {
		p.wg.Add(1)
		go p.runHeartbeat(ctx)
	}
	p.wg.Add(1)
	go p.runLeaseRecovery(ctx)
	p.logger.Info().
		Int("worker_count", p.cfg.WorkerCount).
		Int("lease_seconds", p.cfg.LeaseSeconds).
		Dur("poll_interval", p.cfg.PollInterval).
		Bool("health_poll", p.cfg.HealthPollEnabled).
		Msg("worker pool started")
}

func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.logger.Info().Msg("worker pool stopped")
}

func (p *Pool) runWorker(ctx context.Context, id int) {
	defer p.wg.Done()
	workerID := fmt.Sprintf("%s-embed-%d", p.cfg.WorkerID, id)
	log := p.logger.With().Str("worker_id", workerID).Int("worker_index", id).Logger()
	log.Info().Msg("embedding worker started")

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("embedding worker shutting down")
			return
		case <-ticker.C:
			p.processBatch(ctx, workerID, log)
		}
	}
}

func (p *Pool) processBatch(ctx context.Context, workerID string, logger zerolog.Logger) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		logger.Error().Err(err).Msg("failed to begin transaction")
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()

	leaseDeadline := time.Now().Add(time.Duration(p.cfg.LeaseSeconds) * time.Second)

	jobs, err := claimJobs(ctx, tx, workerID, p.cfg.BatchSize, leaseDeadline)
	if err != nil {
		logger.Error().Err(err).Msg("failed to claim jobs")
		return
	}
	if len(jobs) == 0 {
		if err := tx.Commit(); err != nil {
			logger.Error().Err(err).Msg("failed to commit empty claim transaction")
		}
		return
	}
	if err := tx.Commit(); err != nil {
		logger.Error().Err(err).Msg("failed to commit job claims")
		return
	}

	logger.Info().Int("claimed", len(jobs)).Msg("jobs claimed")
	renewCtx, cancelRenewal := context.WithCancel(ctx)
	defer cancelRenewal()
	go p.renewLeases(renewCtx, jobs, logger)

	completed := 0
	for kind, kindJobs := range groupJobsByKind(jobs) {
		texts := make([]string, len(kindJobs))
		for i := range kindJobs {
			texts[i] = kindJobs[i].NormalizedText
		}
		vectors, embedErr := p.embedder.Embed(ctx, texts, kind)
		if embedErr != nil {
			logger.Error().Err(embedErr).Int("job_count", len(kindJobs)).Str("kind", kind).Msg("embedding batch failed")
			for _, job := range kindJobs {
				p.failClaimedJob(ctx, job, embedErr, logger)
			}
			continue
		}
		if len(vectors) != len(kindJobs) {
			mismatch := fmt.Errorf("embedding count mismatch: expected %d, got %d", len(kindJobs), len(vectors))
			for _, job := range kindJobs {
				p.failClaimedJob(ctx, job, mismatch, logger)
			}
			continue
		}
		for i, job := range kindJobs {
			if err := p.storeCompletion(ctx, job, vectors[i]); err != nil {
				logger.Error().Err(err).Str("job_id", job.JobID).Msg("embedding completion failed")
				p.failClaimedJob(ctx, job, err, logger)
				continue
			}
			completed++
		}
	}

	logger.Info().Int("completed", completed).Int("claimed", len(jobs)).Msg("embedding batch completed")
}

func groupJobsByKind(jobs []Job) map[string][]Job {
	grouped := make(map[string][]Job)
	for _, job := range jobs {
		grouped[job.EmbeddingKind] = append(grouped[job.EmbeddingKind], job)
	}
	return grouped
}

func (p *Pool) storeCompletion(ctx context.Context, job Job, vector []float32) error {
	table, err := vectorTableForKind(job.EmbeddingKind)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertVector(ctx, tx, table, job.DocumentID, job.EmbeddingModel, job.ContentSHA256, vector); err != nil {
		return err
	}
	if err := completeJob(ctx, tx, job.JobID, job.LeaseToken, job.LeaseFence); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Pool) failClaimedJob(ctx context.Context, job Job, cause error, logger zerolog.Logger) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		logger.Error().Err(err).Str("job_id", job.JobID).Msg("failed to begin job failure transaction")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := failJob(ctx, tx, job.JobID, job.LeaseToken, job.LeaseFence, cause.Error()); err != nil {
		logger.Error().Err(err).Str("job_id", job.JobID).Msg("failed to persist embedding failure")
		return
	}
	if err := tx.Commit(); err != nil {
		logger.Error().Err(err).Str("job_id", job.JobID).Msg("failed to commit embedding failure")
	}
}

func (p *Pool) renewLeases(ctx context.Context, jobs []Job, logger zerolog.Logger) {
	interval := time.Duration(p.cfg.LeaseSeconds) * time.Second / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expiresAt := time.Now().Add(time.Duration(p.cfg.LeaseSeconds) * time.Second)
			for _, job := range jobs {
				renewed, err := renewJobLease(ctx, p.db, job, expiresAt)
				if err != nil {
					logger.Error().Err(err).Str("job_id", job.JobID).Msg("embedding lease renewal failed")
				} else if !renewed {
					logger.Warn().Str("job_id", job.JobID).Msg("embedding lease no longer owned")
				}
			}
		}
	}
}

func (p *Pool) runLeaseRecovery(ctx context.Context) {
	defer p.wg.Done()
	interval := p.cfg.PollInterval * 10
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recovered, err := recoverExpiredLeases(ctx, p.db, p.cfg.BatchSize)
			if err != nil {
				p.logger.Error().Err(err).Msg("embedding lease recovery failed")
			} else if recovered > 0 {
				p.logger.Info().Int64("recovered", recovered).Msg("expired embedding leases recovered")
			}
		}
	}
}

func (p *Pool) runHeartbeat(ctx context.Context) {
	defer p.wg.Done()
	workerID := p.cfg.WorkerID
	log := p.logger.With().Str("worker_id", workerID).Logger()
	log.Info().Msg("heartbeat goroutine started")

	interval := p.cfg.PollInterval * 10
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat goroutine shutting down")
			return
		case <-ticker.C:
			if err := upsertHeartbeat(context.Background(), p.db, workerID, "pool", nil); err != nil {
				log.Error().Err(err).Msg("heartbeat update failed")
			}
		}
	}
}
