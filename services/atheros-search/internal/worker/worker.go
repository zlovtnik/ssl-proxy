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
		_ = tx.Commit()
		return
	}

	logger.Info().Int("claimed", len(jobs)).Msg("jobs claimed")

	texts := make([]string, len(jobs))
	for i, j := range jobs {
		texts[i] = j.NormalizedText
	}

	vectors, err := p.embedder.Embed(ctx, texts, jobs[0].EmbeddingKind)
	if err != nil {
		logger.Error().Err(err).Int("job_count", len(jobs)).Msg("embedding batch failed")
		for _, j := range jobs {
			_ = failJob(ctx, tx, j.JobID, j.LeaseToken, err.Error())
		}
		_ = tx.Commit()
		return
	}

	if len(vectors) != len(jobs) {
		logger.Error().
			Int("expected", len(jobs)).
			Int("got", len(vectors)).
			Msg("embedding count mismatch")
		for _, j := range jobs {
			_ = failJob(ctx, tx, j.JobID, j.LeaseToken, "embedding count mismatch")
		}
		_ = tx.Commit()
		return
	}

	for i, j := range jobs {
		table, err := vectorTableForKind(j.EmbeddingKind)
		if err != nil {
			_ = failJob(ctx, tx, j.JobID, j.LeaseToken, err.Error())
			continue
		}
		if err := insertVector(ctx, tx, table, j.DocumentID, j.EmbeddingModel, j.ContentSHA256, vectors[i]); err != nil {
			_ = failJob(ctx, tx, j.JobID, j.LeaseToken, err.Error())
			continue
		}
		if err := completeJob(ctx, tx, j.JobID, j.LeaseToken); err != nil {
			logger.Error().Err(err).Str("job_id", j.JobID).Msg("failed to mark job completed, failing job")
			_ = failJob(ctx, tx, j.JobID, j.LeaseToken, err.Error())
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Error().Err(err).Msg("failed to commit transaction")
		return
	}

	logger.Info().Int("completed", len(jobs)).Msg("embedding batch completed")
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
