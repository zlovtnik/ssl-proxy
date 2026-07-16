package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/textbuilder"
)

var supportedKinds = []string{
	"event",
	"device",
	"behaviour_window",
	"baseline_profile",
	"frame_sequence",
	"infrastructure_subgraph",
	"timing_profile",
}

type candidate struct {
	db.EmbeddingJob
	EmbeddingContentSHA256 string `db:"embedding_content_sha256"`
}

type stats struct {
	scanned  int
	matched  int
	repaired int64
	changed  int
	missing  int
	errors   int
}

func main() {
	var (
		dsn            string
		kindsArg       string
		batchSize      int
		limit          int
		maxInputTokens int
		apply          bool
	)
	flag.StringVar(&dsn, "dsn", firstEnv("ATHSEARCH_POSTGRES_DSN", "DATABASE_URL", "SYNC_DATABASE_URL"), "Postgres DSN")
	flag.StringVar(&kindsArg, "kinds", strings.Join(supportedKinds, ","), "Comma-separated embedding kinds")
	flag.IntVar(&batchSize, "batch-size", 500, "Rows to inspect per batch and kind")
	flag.IntVar(&limit, "limit", 0, "Maximum rows to inspect across all kinds; 0 means no limit")
	flag.IntVar(&maxInputTokens, "max-input-tokens", 512, "Worker input-token limit used before hashing")
	flag.BoolVar(&apply, "apply", false, "Update matched pending jobs to completed")
	flag.Parse()

	if strings.TrimSpace(dsn) == "" {
		fatalf("missing DSN: set -dsn, ATHSEARCH_POSTGRES_DSN, DATABASE_URL, or SYNC_DATABASE_URL")
	}
	if batchSize < 1 {
		fatalf("-batch-size must be >= 1")
	}
	if maxInputTokens < 1 {
		fatalf("-max-input-tokens must be >= 1")
	}

	kinds, err := parseKinds(kindsArg)
	if err != nil {
		fatalf("%v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer pool.Close()

	total := stats{}
	for _, kind := range kinds {
		remaining := remainingLimit(limit, total.scanned)
		if limit > 0 && remaining == 0 {
			break
		}
		kindStats, err := repairKind(ctx, pool, kind, batchSize, remaining, maxInputTokens, apply)
		if err != nil {
			fatalf("repair %s: %v", kind, err)
		}
		total.add(kindStats)
		fmt.Printf(
			"kind=%s scanned=%d matched=%d repaired=%d changed=%d missing=%d errors=%d\n",
			kind,
			kindStats.scanned,
			kindStats.matched,
			kindStats.repaired,
			kindStats.changed,
			kindStats.missing,
			kindStats.errors,
		)
	}

	mode := "dry_run"
	if apply {
		mode = "apply"
	}
	fmt.Printf(
		"mode=%s scanned=%d matched=%d repaired=%d changed=%d missing=%d errors=%d\n",
		mode,
		total.scanned,
		total.matched,
		total.repaired,
		total.changed,
		total.missing,
		total.errors,
	)
}

func repairKind(ctx context.Context, pool *pgxpool.Pool, kind string, batchSize int, limit int, maxInputTokens int, apply bool) (stats, error) {
	out := stats{}
	var lastJobID int64
	for {
		if limit > 0 && out.scanned >= limit {
			return out, nil
		}
		currentBatchSize := batchSize
		if limit > 0 && limit-out.scanned < currentBatchSize {
			currentBatchSize = limit - out.scanned
		}

		rows, err := loadCandidates(ctx, pool, kind, lastJobID, currentBatchSize)
		if err != nil {
			return out, err
		}
		if len(rows) == 0 {
			return out, nil
		}
		out.scanned += len(rows)
		lastJobID = rows[len(rows)-1].JobID

		jobs := make([]db.EmbeddingJob, 0, len(rows))
		byID := make(map[int64]candidate, len(rows))
		for _, row := range rows {
			jobs = append(jobs, row.EmbeddingJob)
			byID[row.JobID] = row
		}

		inputs, err := textbuilder.BuildBatch(ctx, pool, jobs)
		if err != nil {
			out.errors += len(rows)
			return out, err
		}

		matchedIDs := make([]int64, 0, len(rows))
		for _, job := range jobs {
			row := byID[job.JobID]
			input, ok := inputs[job.SourceKey]
			if !ok {
				out.missing++
				continue
			}
			currentHash := contentSHA256(truncateInputText(input.Text, maxInputTokens))
			if strings.EqualFold(currentHash, row.EmbeddingContentSHA256) {
				out.matched++
				matchedIDs = append(matchedIDs, job.JobID)
			} else {
				out.changed++
			}
		}

		if apply && len(matchedIDs) > 0 {
			repaired, err := markCompleted(ctx, pool, matchedIDs)
			if err != nil {
				return out, err
			}
			out.repaired += repaired
		}
	}
}

func loadCandidates(ctx context.Context, pool *pgxpool.Pool, kind string, afterJobID int64, limit int) ([]candidate, error) {
	rows, err := pool.Query(ctx, `
SELECT
  j.job_id,
  j.source_table,
  j.source_key,
  j.embedding_model,
  j.embedding_kind,
  j.status,
  j.priority,
  j.attempts,
  j.max_attempts,
  j.lease_token,
  j.leased_at,
  j.locked_by,
  j.due_at,
  j.content_sha256,
  j.last_error,
  j.completed_at,
  j.created_at,
  j.updated_at,
  e.content_sha256 AS embedding_content_sha256
FROM vec_embedding_jobs_expanded j
JOIN vec_embeddings_expanded e
  ON e.source_table = j.source_table
 AND e.source_key = j.source_key
 AND e.embedding_model = j.embedding_model
 AND e.embedding_kind = j.embedding_kind
WHERE j.status = 'pending'
  AND j.embedding_kind = $1
  AND j.job_id > $2
ORDER BY j.job_id ASC
LIMIT $3
`, kind, afterJobID, limit)
	if err != nil {
		return nil, fmt.Errorf("query candidates: %w", err)
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[candidate])
}

func markCompleted(ctx context.Context, pool *pgxpool.Pool, jobIDs []int64) (int64, error) {
	tag, err := pool.Exec(ctx, `
WITH jobs_completed AS (
  UPDATE vec_embedding_jobs job
  SET status = 'completed',
      content_sha256 = embedding.content_sha256,
      updated_at = now()
  FROM vec_embeddings_expanded embedding
  WHERE job.job_id = ANY($1::bigint[])
    AND job.status = 'pending'
    AND embedding.source_table = job.source_table
    AND embedding.source_key = job.source_key
    AND embedding.embedding_model = job.embedding_model
    AND embedding.embedding_kind = job.embedding_kind
  RETURNING job.job_id
)
UPDATE vec_embedding_job_leases lease
SET completed_at = now(),
    lease_token = NULL,
    leased_at = NULL,
    locked_by = NULL,
    last_error = NULL
FROM jobs_completed
WHERE lease.job_id = jobs_completed.job_id
`, jobIDs)
	if err != nil {
		return 0, fmt.Errorf("mark completed: %w", err)
	}
	return tag.RowsAffected(), nil
}

func parseKinds(raw string) ([]string, error) {
	allowed := map[string]struct{}{}
	for _, kind := range supportedKinds {
		allowed[kind] = struct{}{}
	}

	seen := map[string]struct{}{}
	kinds := []string{}
	for _, item := range strings.Split(raw, ",") {
		kind := strings.ToLower(strings.TrimSpace(item))
		if kind == "" {
			continue
		}
		if _, ok := allowed[kind]; !ok {
			return nil, fmt.Errorf("unsupported embedding kind %q", kind)
		}
		if _, ok := seen[kind]; ok {
			continue
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}
	if len(kinds) == 0 {
		return nil, fmt.Errorf("no embedding kinds selected")
	}
	sort.Slice(kinds, func(i, j int) bool {
		return kindRank(kinds[i]) < kindRank(kinds[j])
	})
	return kinds, nil
}

func kindRank(kind string) int {
	for i, supported := range supportedKinds {
		if supported == kind {
			return i
		}
	}
	return len(supportedKinds)
}

func truncateInputText(text string, maxInputTokens int) string {
	maxChars := maxInputTokens * 3 / 2
	if maxChars <= 0 || len(text) <= maxChars {
		return text
	}
	cut := strings.LastIndex(text[:maxChars], "\n")
	if cut <= 0 {
		cut = maxChars
	}
	return text[:cut] + "\n[truncated]"
}

func contentSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func remainingLimit(limit int, scanned int) int {
	if limit <= 0 {
		return 0
	}
	remaining := limit - scanned
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (s *stats) add(other stats) {
	s.scanned += other.scanned
	s.matched += other.matched
	s.repaired += other.repaired
	s.changed += other.changed
	s.missing += other.missing
	s.errors += other.errors
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
