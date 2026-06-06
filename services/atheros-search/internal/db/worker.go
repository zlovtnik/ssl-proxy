package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EmbeddingJob struct {
	JobID          int64      `db:"job_id"`
	SourceTable    string     `db:"source_table"`
	SourceKey      string     `db:"source_key"`
	EmbeddingModel string     `db:"embedding_model"`
	EmbeddingKind  string     `db:"embedding_kind"`
	Status         string     `db:"status"`
	Priority       int32      `db:"priority"`
	Attempts       int32      `db:"attempts"`
	MaxAttempts    int32      `db:"max_attempts"`
	LeaseToken     *string    `db:"lease_token"`
	LeasedAt       *time.Time `db:"leased_at"`
	LockedBy       *string    `db:"locked_by"`
	DueAt          time.Time  `db:"due_at"`
	ContentSHA256  *string    `db:"content_sha256"`
	LastError      *string    `db:"last_error"`
	CompletedAt    *time.Time `db:"completed_at"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
}

type CompleteBatchRow struct {
	JobID               int64          `json:"job_id"`
	LeaseToken          *string        `json:"lease_token"`
	SourceTable         string         `json:"source_table"`
	SourceKey           string         `json:"source_key"`
	SourceObservedAt    *time.Time     `json:"source_observed_at,omitempty"`
	SourceStreamName    string         `json:"source_stream_name,omitempty"`
	SourceSensorID      string         `json:"source_sensor_id,omitempty"`
	SourceLocationID    string         `json:"source_location_id,omitempty"`
	SourceMAC           string         `json:"source_mac,omitempty"`
	EmbeddingModel      string         `json:"embedding_model"`
	EmbeddingKind       string         `json:"embedding_kind"`
	EmbeddingDimensions int            `json:"embedding_dimensions"`
	ContentSHA256       string         `json:"content_sha256"`
	ContentText         string         `json:"content_text"`
	Embedding           string         `json:"embedding"`
	Metadata            map[string]any `json:"metadata"`
	ExplanationText     *string        `json:"explanation_text,omitempty"`
}

type WorkerStateParams struct {
	WorkerName        string
	Status            string
	LastCursor        *string
	LastRunStartedAt  *time.Time
	LastRunFinishedAt *time.Time
	RowsProcessed     int64
	LastError         *string
}

type EmbeddingInput struct {
	Text             string
	SourceObservedAt *time.Time
	SourceStreamName string
	SourceSensorID   string
	SourceLocationID string
	SourceMAC        string
}

func LeaseJobs(ctx context.Context, pool *pgxpool.Pool, batchSize int, workerName string, leaseSeconds int) ([]EmbeddingJob, error) {
	rows, err := pool.Query(ctx,
		"SELECT * FROM vec_lease_embedding_jobs($1, $2, make_interval(secs => $3))",
		batchSize, workerName, leaseSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("lease embedding jobs: %w", err)
	}
	defer rows.Close()

	jobs, err := pgx.CollectRows(rows, pgx.RowToStructByName[EmbeddingJob])
	if err != nil {
		return nil, fmt.Errorf("collect leased embedding jobs: %w", err)
	}
	return jobs, nil
}

func CompleteEmbeddingBatch(ctx context.Context, pool *pgxpool.Pool, rows []CompleteBatchRow) (int32, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, fmt.Errorf("marshal embedding batch completion: %w", err)
	}
	var completed int32
	err = pool.QueryRow(ctx,
		"SELECT vec_complete_embedding_batch($1::jsonb)", string(payload),
	).Scan(&completed)
	if err != nil {
		return 0, fmt.Errorf("complete embedding batch: %w", err)
	}
	return completed, nil
}

func CompleteOneEmbedding(ctx context.Context, pool *pgxpool.Pool, row CompleteBatchRow) (bool, error) {
	payload, err := json.Marshal(row)
	if err != nil {
		return false, fmt.Errorf("marshal embedding completion: %w", err)
	}
	var completed bool
	err = pool.QueryRow(ctx,
		"SELECT vec_complete_one_embedding($1::jsonb)", string(payload),
	).Scan(&completed)
	if err != nil {
		return false, fmt.Errorf("complete one embedding: %w", err)
	}
	return completed, nil
}

func FailJob(ctx context.Context, pool *pgxpool.Pool, jobID int64, leaseToken *string, attempts, maxAttempts int32, msg string) error {
	tag, err := pool.Exec(ctx, `
UPDATE vec_embedding_jobs
SET status = CASE WHEN $2 >= $3 THEN 'failed' ELSE 'pending' END,
    lease_token = NULL,
    leased_at = NULL,
    locked_by = NULL,
    last_error = $1,
    due_at = now() + make_interval(secs => $4),
    updated_at = now()
WHERE job_id = $5
  AND lease_token IS NOT DISTINCT FROM $6
`, msg, attempts, maxAttempts, backoffSeconds(attempts), jobID, leaseToken)
	if err != nil {
		return fmt.Errorf("fail embedding job: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func MarkWorkerState(ctx context.Context, pool *pgxpool.Pool, params WorkerStateParams) error {
	_, err := pool.Exec(ctx, `
INSERT INTO vec_worker_state (
    worker_name, status, last_cursor, last_run_started_at,
    last_run_finished_at, rows_processed, last_error, updated_at
)
VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, now()
)
ON CONFLICT (worker_name) DO UPDATE SET
    status = EXCLUDED.status,
    last_cursor = COALESCE(EXCLUDED.last_cursor, vec_worker_state.last_cursor),
    last_run_started_at = COALESCE(EXCLUDED.last_run_started_at, vec_worker_state.last_run_started_at),
    last_run_finished_at = COALESCE(EXCLUDED.last_run_finished_at, vec_worker_state.last_run_finished_at),
    rows_processed = CASE
        WHEN EXCLUDED.rows_processed > 0
        THEN vec_worker_state.rows_processed + EXCLUDED.rows_processed
        ELSE vec_worker_state.rows_processed
    END,
    last_error = EXCLUDED.last_error,
    updated_at = now()
`, params.WorkerName, params.Status, params.LastCursor, params.LastRunStartedAt,
		params.LastRunFinishedAt, params.RowsProcessed, params.LastError)
	if err != nil {
		return fmt.Errorf("mark worker state: %w", err)
	}
	return nil
}

func ReleaseExpiredLeases(ctx context.Context, pool *pgxpool.Pool) (int32, error) {
	var released int32
	if err := pool.QueryRow(ctx, "SELECT vec_release_expired_leases()").Scan(&released); err != nil {
		return 0, fmt.Errorf("release expired leases: %w", err)
	}
	return released, nil
}

func TryBeginAlertSweep(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var acquired bool
	if err := pool.QueryRow(ctx, "SELECT vec_try_begin_maintenance_job('alert-sweep')").Scan(&acquired); err != nil {
		return false, fmt.Errorf("begin alert sweep: %w", err)
	}
	return acquired, nil
}

func FinishAlertSweep(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, "SELECT vec_finish_maintenance_job('alert-sweep')"); err != nil {
		return fmt.Errorf("finish alert sweep: %w", err)
	}
	return nil
}

func CompletedJobIDs(ctx context.Context, pool *pgxpool.Pool, jobIDs []int64) (map[int64]struct{}, error) {
	completed := make(map[int64]struct{}, len(jobIDs))
	if len(jobIDs) == 0 {
		return completed, nil
	}
	rows, err := pool.Query(ctx, `
SELECT job_id
FROM vec_embedding_jobs
WHERE job_id = ANY($1::bigint[])
  AND status = 'completed'
`, jobIDs)
	if err != nil {
		return nil, fmt.Errorf("query completed embedding jobs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var jobID int64
		if err := rows.Scan(&jobID); err != nil {
			return nil, fmt.Errorf("scan completed embedding job: %w", err)
		}
		completed[jobID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read completed embedding jobs: %w", err)
	}
	return completed, nil
}

func CountHighRiskAPs(ctx context.Context, pool *pgxpool.Pool, threshold float64) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM mv_ap_risk_score WHERE composite_risk > $1", threshold,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count high-risk APs: %w", err)
	}
	return count, nil
}

func CountWorkerQueueDepth(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx,
		"SELECT count(*) FROM vec_embedding_jobs WHERE status IN ('pending', 'failed')",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count worker queue depth: %w", err)
	}
	return count, nil
}

func backoffSeconds(attempts int32) int32 {
	raw := int64(attempts) * 10
	if raw < 10 {
		return 10
	}
	if raw > 300 {
		return 300
	}
	return int32(raw)
}
