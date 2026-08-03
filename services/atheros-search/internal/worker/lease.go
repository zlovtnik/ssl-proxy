package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func claimJobs(ctx context.Context, tx *sql.Tx, ownerID string, limit int, leaseExpiresAt time.Time) ([]Job, error) {
	rows, err := tx.QueryContext(ctx, `
UPDATE embedding_jobs
SET status = 'leased',
    owner_id = ?,
    lease_token = UUID(),
    lease_fence = lease_fence + 1,
    lease_expires_at = ?,
    attempt_count = attempt_count + 1,
    updated_at = CURRENT_TIMESTAMP(6)
WHERE job_id IN (
  SELECT job_id FROM (
    SELECT job_id
    FROM embedding_jobs
    WHERE status = 'pending'
      AND next_attempt_at <= NOW(6)
      AND attempt_count < max_attempts
    ORDER BY priority ASC, next_attempt_at ASC
    LIMIT ?
  ) AS candidates
)
RETURNING job_id, document_id, embedding_kind, embedding_model, content_sha256, priority, lease_token, lease_fence
`, ownerID, leaseExpiresAt, limit)
	if err != nil {
		return nil, fmt.Errorf("claim embedding jobs: %w", err)
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.JobID, &j.DocumentID, &j.EmbeddingKind, &j.EmbeddingModel, &j.ContentSHA256, &j.Priority, &j.LeaseToken, &j.LeaseFence); err != nil {
			return nil, fmt.Errorf("scan claimed job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed jobs: %w", err)
	}

	for i := range jobs {
		err := tx.QueryRowContext(ctx, `
SELECT normalized_text FROM search_documents WHERE document_id = ?
`, jobs[i].DocumentID).Scan(&jobs[i].NormalizedText)
		if err != nil {
			return nil, fmt.Errorf("fetch document text for %s: %w", jobs[i].DocumentID, err)
		}
	}

	return jobs, nil
}

func completeJob(ctx context.Context, tx *sql.Tx, jobID, leaseToken string, leaseFence int64) error {
	result, err := tx.ExecContext(ctx, `
UPDATE embedding_jobs
SET status = 'completed',
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    completed_at = CURRENT_TIMESTAMP(6),
    updated_at = CURRENT_TIMESTAMP(6)
WHERE job_id = ? AND lease_token = ? AND lease_fence = ? AND lease_expires_at > NOW(6)
`, jobID, leaseToken, leaseFence)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("lease lost for job %s: no matching lease token or lease expired", jobID)
	}
	return nil
}

func failJob(ctx context.Context, tx *sql.Tx, jobID, leaseToken string, leaseFence int64, errMsg string) error {
	maxBackoff := 300 * time.Second
	result, err := tx.ExecContext(ctx, `
UPDATE embedding_jobs
SET status = CASE
        WHEN attempt_count >= max_attempts THEN 'failed'
        ELSE 'pending'
    END,
    last_error = ?,
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    next_attempt_at = DATE_ADD(NOW(6), INTERVAL LEAST(POW(2, attempt_count), ?) SECOND),
    updated_at = CURRENT_TIMESTAMP(6)
WHERE job_id = ? AND lease_token = ? AND lease_fence = ? AND lease_expires_at > NOW(6)
`, errMsg, int(maxBackoff.Seconds()), jobID, leaseToken, leaseFence)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("lease lost for job %s: no matching lease token or lease expired", jobID)
	}
	return nil
}

func renewJobLease(ctx context.Context, db *sql.DB, job Job, leaseExpiresAt time.Time) (bool, error) {
	result, err := db.ExecContext(ctx, `
UPDATE embedding_jobs
SET lease_expires_at = ?, updated_at = CURRENT_TIMESTAMP(6)
WHERE job_id = ?
  AND status = 'leased'
  AND lease_token = ?
  AND lease_fence = ?
  AND lease_expires_at > NOW(6)
`, leaseExpiresAt, job.JobID, job.LeaseToken, job.LeaseFence)
	if err != nil {
		return false, fmt.Errorf("renew embedding lease: %w", err)
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func recoverExpiredLeases(ctx context.Context, db *sql.DB, limit int) (int64, error) {
	result, err := db.ExecContext(ctx, `
UPDATE embedding_jobs
SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'pending' END,
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    last_error = CASE
      WHEN attempt_count >= max_attempts THEN 'embedding lease expired; retries exhausted'
      ELSE 'embedding lease expired; returned to pending'
    END,
    next_attempt_at = DATE_ADD(NOW(6), INTERVAL LEAST(POW(2, attempt_count), 300) SECOND),
    updated_at = CURRENT_TIMESTAMP(6)
WHERE job_id IN (
  SELECT job_id FROM (
    SELECT job_id
    FROM embedding_jobs
    WHERE status = 'leased' AND lease_expires_at <= NOW(6)
    ORDER BY lease_expires_at, job_id
    LIMIT ?
  ) AS expired
)
`, limit)
	if err != nil {
		return 0, fmt.Errorf("recover expired embedding leases: %w", err)
	}
	return result.RowsAffected()
}

func vectorTableForKind(kind string) (string, error) {
	switch kind {
	case "event":
		return "search_vectors_event", nil
	case "device":
		return "search_vectors_device", nil
	case "behaviour", "behaviour_window":
		return "search_vectors_behaviour", nil
	case "sequence", "frame_sequence":
		return "search_vectors_sequence", nil
	default:
		return "", fmt.Errorf("unknown embedding kind: %s", kind)
	}
}

func insertVector(ctx context.Context, tx *sql.Tx, table, documentID, embeddingModel, contentSHA256 string, embedding []float32) error {
	vecStr := formatVector(embedding)
	query := fmt.Sprintf(`
INSERT INTO %s (document_id, embedding_model, content_sha256, embedding, embedded_at)
VALUES (?, ?, ?, VEC_FROM_TEXT(?), NOW(6))
ON DUPLICATE KEY UPDATE
  embedding = VALUES(embedding),
  content_sha256 = VALUES(content_sha256),
  embedded_at = NOW(6)
`, table)
	_, err := tx.ExecContext(ctx, query, documentID, embeddingModel, contentSHA256, vecStr)
	return err
}

func formatVector(v []float32) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func upsertHeartbeat(ctx context.Context, db *sql.DB, workerID, workerType string, metadata json.RawMessage) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO worker_heartbeat (worker_id, worker_type, last_seen_at, metadata)
VALUES (?, ?, NOW(6), ?)
ON DUPLICATE KEY UPDATE last_seen_at = NOW(6), metadata = VALUES(metadata)
`, workerID, workerType, metadata)
	return err
}

func staleJobs(ctx context.Context, db *sql.DB, staleThreshold time.Duration) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs
WHERE (status = 'leased' AND lease_expires_at < ?)
   OR (status = 'pending' AND next_attempt_at <= NOW(6))
`, time.Now().Add(-staleThreshold)).Scan(&count)
	return count, err
}

func pendingJobCount(ctx context.Context, db *sql.DB) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'pending'
`).Scan(&count)
	return count, err
}

func failedJobCount(ctx context.Context, db *sql.DB) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'failed'
`).Scan(&count)
	return count, err
}
