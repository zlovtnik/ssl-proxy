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
  wireless_events_24h_count,
  wireless_last_observed_at,
  ingest_pending_count,
  ingest_processing_count,
  ingest_failed_count,
  batch_pending_count,
  batch_processing_count,
  batch_completed_count,
  batch_failed_count,
  job_stored_pending_count,
  job_stored_running_count,
  job_stored_completed_count,
  job_stored_failed_count,
  job_effective_pending_count,
  job_effective_running_count,
  job_effective_completed_count,
  job_effective_failed_count,
  job_orphaned_count,
  backlog_pending_count,
  backlog_failed_count
FROM atheros_search.v_sync_plane_health
WHERE projection_key = 'current'
LIMIT 1
`).Scan(
		&health.WirelessEvents24h,
		&health.WirelessLastObservedAt,
		&health.IngestPending,
		&health.IngestProcessing,
		&health.IngestFailed,
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
	if err != nil && err != sql.ErrNoRows {
		return health, err
	}

	embedErr := h.db.QueryRowContext(ctx, `
SELECT
  SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END),
  SUM(CASE WHEN status = 'leased' THEN 1 ELSE 0 END),
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END),
  SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
FROM atheros_search.embedding_jobs
`).Scan(
		&health.EmbeddingPending,
		&health.EmbeddingLeased,
		&health.EmbeddingCompleted,
		&health.EmbeddingFailed,
	)
	if embedErr != nil && embedErr != sql.ErrNoRows {
		return health, embedErr
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

	return health, nil
}
