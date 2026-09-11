package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type ETLHealth struct {
	MeasuredAt             time.Time         `json:"measured_at"`
	WirelessEvents24h      int64             `json:"wireless_events_24h"`
	WirelessLastObservedAt *time.Time        `json:"wireless_last_observed_at,omitempty"`
	IngestPending          int64             `json:"ingest_pending"`
	IngestProcessing       int64             `json:"ingest_processing"`
	IngestFailed           int64             `json:"ingest_failed"`
	BatchPending           int64             `json:"batch_pending"`
	BatchProcessing        int64             `json:"batch_processing"`
	BatchCompleted         int64             `json:"batch_completed"`
	BatchFailed            int64             `json:"batch_failed"`
	JobStoredPending       int64             `json:"job_stored_pending"`
	JobStoredRunning       int64             `json:"job_stored_running"`
	JobStoredCompleted     int64             `json:"job_stored_completed"`
	JobStoredFailed        int64             `json:"job_stored_failed"`
	JobEffectivePending    int64             `json:"job_effective_pending"`
	JobEffectiveRunning    int64             `json:"job_effective_running"`
	JobEffectiveCompleted  int64             `json:"job_effective_completed"`
	JobEffectiveFailed     int64             `json:"job_effective_failed"`
	JobOrphaned            int64             `json:"job_orphaned"`
	BacklogPending         int64             `json:"backlog_pending"`
	BacklogFailed          int64             `json:"backlog_failed"`
	EmbeddingPending       int64             `json:"embedding_pending"`
	EmbeddingLeased        int64             `json:"embedding_leased"`
	EmbeddingCompleted     int64             `json:"embedding_completed"`
	EmbeddingFailed        int64             `json:"embedding_failed"`
	EmbeddingRetryCount    int64             `json:"embedding_retry_count"`
	OldestEmbeddingJobAt   *time.Time        `json:"oldest_embedding_job_at,omitempty"`
	EmbeddingDependency    string            `json:"embedding_dependency"`
	Workers                []WorkerHeartbeat `json:"workers"`
}

type WorkerHeartbeat struct {
	WorkerID   string          `json:"worker_id"`
	WorkerType string          `json:"worker_type"`
	LastSeenAt time.Time       `json:"last_seen_at"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type HealthMonitor struct {
	db     *sql.DB
	logger interface {
		Debug() interface{ Msg(string) }
	}
}

func NewHealthMonitor(db *sql.DB) *HealthMonitor {
	return &HealthMonitor{db: db}
}

func (h *HealthMonitor) Snapshot(ctx context.Context) (ETLHealth, error) {
	var health ETLHealth
	health.MeasuredAt = time.Now().UTC()

	err := h.db.QueryRowContext(ctx, `
SELECT
  COUNT(*) FILTER (WHERE observed_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'),
  MAX(observed_at)
FROM octopus_core.wireless_observations
`).Scan(
		&health.WirelessEvents24h,
		&health.WirelessLastObservedAt,
	)
	if err != nil {
		return health, err
	}

	err = h.db.QueryRowContext(ctx, `
SELECT
  COUNT(*) FILTER (WHERE disposition = 'received'),
  COUNT(*) FILTER (WHERE disposition = 'processing'),
  COUNT(*) FILTER (WHERE disposition IN ('rejected', 'failed'))
FROM octopus_core.ingestion_receipts
`).Scan(
		&health.IngestPending,
		&health.IngestProcessing,
		&health.IngestFailed,
	)
	if err != nil {
		return health, err
	}

	err = h.db.QueryRowContext(ctx, `
SELECT
  COUNT(*) FILTER (WHERE work_kind = 'batch' AND status = 'pending'),
  COUNT(*) FILTER (WHERE work_kind = 'batch' AND status IN ('leased', 'running')),
  COUNT(*) FILTER (WHERE work_kind = 'batch' AND status = 'completed'),
  COUNT(*) FILTER (WHERE work_kind = 'batch' AND status = 'failed'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'pending'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status IN ('leased', 'running')),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'completed'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'failed'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'pending'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status IN ('leased', 'running')),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'completed'),
  COUNT(*) FILTER (WHERE work_kind = 'job' AND status = 'failed'),
  COUNT(*) FILTER (WHERE status IN ('leased', 'running') AND lease_expires_at <= CURRENT_TIMESTAMP),
  COUNT(*) FILTER (WHERE work_kind = 'backlog' AND status = 'pending'),
  COUNT(*) FILTER (WHERE work_kind = 'backlog' AND status = 'failed')
FROM octopus_core.work_items
`).Scan(
		&health.BatchPending,
		&health.BatchProcessing,
		&health.BatchCompleted,
		&health.BatchFailed,
		&health.JobStoredPending,
		&health.JobStoredRunning,
		&health.JobStoredCompleted,
		&health.JobStoredFailed,
		&health.JobEffectivePending,
		&health.JobEffectiveRunning,
		&health.JobEffectiveCompleted,
		&health.JobEffectiveFailed,
		&health.JobOrphaned,
		&health.BacklogPending,
		&health.BacklogFailed,
	)
	if err != nil {
		return health, err
	}

	embedErr := h.db.QueryRowContext(ctx, `
SELECT
  COUNT(*) FILTER (WHERE status = 'pending'),
  COUNT(*) FILTER (WHERE status = 'leased'),
  COUNT(*) FILTER (WHERE status = 'completed'),
  COUNT(*) FILTER (WHERE status = 'failed'),
  COALESCE(SUM(attempt_count) FILTER (WHERE status IN ('pending', 'leased', 'failed')), 0),
  MIN(created_at) FILTER (WHERE status IN ('pending', 'leased'))
FROM atheros_search.embedding_jobs
`).Scan(
		&health.EmbeddingPending,
		&health.EmbeddingLeased,
		&health.EmbeddingCompleted,
		&health.EmbeddingFailed,
		&health.EmbeddingRetryCount,
		&health.OldestEmbeddingJobAt,
	)
	if embedErr != nil && embedErr != sql.ErrNoRows {
		return health, embedErr
	}
	if health.EmbeddingFailed > 0 {
		health.EmbeddingDependency = "blocked"
	} else if health.EmbeddingPending > 0 && len(health.Workers) == 0 {
		health.EmbeddingDependency = "waiting_for_worker"
	} else if health.EmbeddingPending == 0 && health.EmbeddingCompleted == 0 {
		health.EmbeddingDependency = "waiting_for_source"
	} else {
		health.EmbeddingDependency = "healthy"
	}

	rows, err := h.db.QueryContext(ctx, `
SELECT worker_id, worker_type, last_seen_at, metadata
FROM atheros_search.worker_heartbeat
ORDER BY worker_id
`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var wh WorkerHeartbeat
			if err := rows.Scan(&wh.WorkerID, &wh.WorkerType, &wh.LastSeenAt, &wh.Metadata); err != nil {
				continue
			}
			health.Workers = append(health.Workers, wh)
		}
	}
	if health.EmbeddingPending > 0 && len(health.Workers) == 0 {
		health.EmbeddingDependency = "waiting_for_worker"
	}

	return health, nil
}
