package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type DLQEntry struct {
	DedupeKey    string          `json:"dedupe_key"`
	StreamName   string          `json:"stream_name"`
	Payload      json.RawMessage `json:"payload"`
	FailureStage string          `json:"failure_stage"`
	LastError    string          `json:"last_error"`
}

type DLQManager struct {
	db *sql.DB
}

func NewDLQManager(db *sql.DB) *DLQManager {
	return &DLQManager{db: db}
}

func (d *DLQManager) Enqueue(ctx context.Context, dedupeKey, streamName string, payload json.RawMessage, failureStage, lastError string) error {
	if failureStage != "pre_publish" && failureStage != "post_publish" {
		failureStage = "pre_publish"
	}
	_, err := d.db.ExecContext(ctx, `
INSERT INTO sync_backlog (dedupe_key, stream_name, payload, failure_stage, status, last_error)
VALUES (?, ?, ?, ?, 'pending', ?)
ON DUPLICATE KEY UPDATE
  attempt_count = attempt_count + 1,
  failure_stage = VALUES(failure_stage),
  last_error = VALUES(last_error),
  updated_at = CURRENT_TIMESTAMP(6)
`, dedupeKey, streamName, payload, failureStage, lastError)
	return err
}

func (d *DLQManager) PendingCount(ctx context.Context) (int64, error) {
	var count int64
	err := d.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sync_backlog WHERE status = 'pending'
`).Scan(&count)
	return count, err
}

func (d *DLQManager) FailedCount(ctx context.Context) (int64, error) {
	var count int64
	err := d.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sync_backlog WHERE status IN ('sync_failed', 'failed')
`).Scan(&count)
	return count, err
}

func (d *DLQManager) ListPending(ctx context.Context, limit int) ([]DLQEntry, error) {
	if limit < 1 {
		limit = 100
	}
	rows, err := d.db.QueryContext(ctx, `
SELECT dedupe_key, stream_name, payload, failure_stage, COALESCE(last_error, '')
FROM sync_backlog
WHERE status = 'pending'
ORDER BY created_at ASC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending DLQ entries: %w", err)
	}
	defer rows.Close()

	var entries []DLQEntry
	for rows.Next() {
		var e DLQEntry
		if err := rows.Scan(&e.DedupeKey, &e.StreamName, &e.Payload, &e.FailureStage, &e.LastError); err != nil {
			return nil, fmt.Errorf("scan DLQ entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (d *DLQManager) Retry(ctx context.Context, dedupeKey, streamName string) error {
	_, err := d.db.ExecContext(ctx, `
UPDATE sync_backlog
SET status = 'pending',
    next_attempt_at = NOW(6),
    updated_at = CURRENT_TIMESTAMP(6)
WHERE dedupe_key = ? AND stream_name = ? AND status IN ('sync_failed', 'failed')
`, dedupeKey, streamName)
	return err
}

func (d *DLQManager) Evict(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan < time.Second {
		return 0, fmt.Errorf("olderThan must be at least 1 second, got %v", olderThan)
	}
	result, err := d.db.ExecContext(ctx, `
DELETE FROM sync_backlog
WHERE status IN ('sync_failed', 'failed')
  AND updated_at < DATE_SUB(NOW(6), INTERVAL ? SECOND)
`, int(olderThan.Seconds()))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
