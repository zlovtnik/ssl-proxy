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
WITH candidates AS (
  SELECT job_id
  FROM atheros_search.embedding_jobs
  WHERE status = 'pending'
    AND next_attempt_at <= CURRENT_TIMESTAMP
    AND attempt_count < max_attempts
  ORDER BY priority ASC, next_attempt_at ASC, job_id ASC
  FOR UPDATE SKIP LOCKED
  LIMIT $3
)
UPDATE atheros_search.embedding_jobs AS jobs
SET status = 'leased',
    owner_id = $1,
    lease_token = gen_random_uuid(),
    lease_fence = lease_fence + 1,
    lease_expires_at = $2,
    attempt_count = attempt_count + 1,
    updated_at = CURRENT_TIMESTAMP
FROM candidates
WHERE jobs.job_id = candidates.job_id
RETURNING jobs.job_id, jobs.document_id, jobs.embedding_kind, jobs.embedding_model,
          jobs.content_sha256, jobs.priority, jobs.lease_token, jobs.lease_fence
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
SELECT normalized_text FROM atheros_search.search_documents WHERE document_id = $1
`, jobs[i].DocumentID).Scan(&jobs[i].NormalizedText)
		if err != nil {
			return nil, fmt.Errorf("fetch document text for %s: %w", jobs[i].DocumentID, err)
		}
	}

	return jobs, nil
}

func completeJob(ctx context.Context, tx *sql.Tx, jobID, leaseToken string, leaseFence int64) error {
	result, err := tx.ExecContext(ctx, `
UPDATE atheros_search.embedding_jobs
SET status = 'completed',
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    completed_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE job_id = $1
  AND status = 'leased'
  AND lease_token = $2
  AND lease_fence = $3
  AND lease_expires_at > CURRENT_TIMESTAMP
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
UPDATE atheros_search.embedding_jobs
SET status = CASE
        WHEN attempt_count >= max_attempts THEN 'failed'
        ELSE 'pending'
    END,
    last_error = $1,
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    next_attempt_at = CURRENT_TIMESTAMP + LEAST(POWER(2, attempt_count), $2) * INTERVAL '1 second',
    updated_at = CURRENT_TIMESTAMP
WHERE job_id = $3
  AND status = 'leased'
  AND lease_token = $4
  AND lease_fence = $5
  AND lease_expires_at > CURRENT_TIMESTAMP
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
UPDATE atheros_search.embedding_jobs
SET lease_expires_at = $1, updated_at = CURRENT_TIMESTAMP
WHERE job_id = $2
  AND status = 'leased'
  AND lease_token = $3
  AND lease_fence = $4
  AND lease_expires_at > CURRENT_TIMESTAMP
`, leaseExpiresAt, job.JobID, job.LeaseToken, job.LeaseFence)
	if err != nil {
		return false, fmt.Errorf("renew embedding lease: %w", err)
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func recoverExpiredLeases(ctx context.Context, db *sql.DB, limit int) (int64, error) {
	result, err := db.ExecContext(ctx, `
WITH expired AS (
  SELECT job_id
  FROM atheros_search.embedding_jobs
  WHERE status = 'leased' AND lease_expires_at <= CURRENT_TIMESTAMP
  ORDER BY lease_expires_at, job_id
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE atheros_search.embedding_jobs AS jobs
SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'pending' END,
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    last_error = CASE
      WHEN attempt_count >= max_attempts THEN 'embedding lease expired; retries exhausted'
      ELSE 'embedding lease expired; returned to pending'
    END,
    next_attempt_at = CURRENT_TIMESTAMP + LEAST(POWER(2, jobs.attempt_count), 300) * INTERVAL '1 second',
    updated_at = CURRENT_TIMESTAMP
FROM expired
WHERE jobs.job_id = expired.job_id
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
INSERT INTO atheros_search.%s (document_id, embedding_model, content_sha256, embedding, embedded_at)
VALUES ($1, $2, $3, $4::vector, CURRENT_TIMESTAMP)
ON CONFLICT (document_id) DO UPDATE SET
  embedding = EXCLUDED.embedding,
  content_sha256 = EXCLUDED.content_sha256,
  embedded_at = CURRENT_TIMESTAMP
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
INSERT INTO atheros_search.worker_heartbeat (worker_id, worker_type, last_seen_at, metadata)
VALUES ($1, $2, CURRENT_TIMESTAMP, $3)
ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP, metadata = EXCLUDED.metadata
`, workerID, workerType, metadata)
	return err
}

func staleJobs(ctx context.Context, db *sql.DB, staleThreshold time.Duration) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs
WHERE (status = 'leased' AND lease_expires_at < $1)
   OR (status = 'pending' AND next_attempt_at <= CURRENT_TIMESTAMP)
`, time.Now().Add(-staleThreshold)).Scan(&count)
	return count, err
}

func pendingJobCount(ctx context.Context, db *sql.DB) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'pending'
`).Scan(&count)
	return count, err
}

func failedJobCount(ctx context.Context, db *sql.DB) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'failed'
`).Scan(&count)
	return count, err
}
