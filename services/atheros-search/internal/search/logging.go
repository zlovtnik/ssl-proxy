package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func LogQuery(ctx context.Context, pool *pgxpool.Pool, queryText, queryKind string, qvec []float32, topK int, resultKeys []string, sessionID string, latencyMS int64) (int64, error) {
	var queryID int64
	var vec any
	if len(qvec) > 0 {
		vec = VectorLiteral(qvec)
	}
	err := pool.QueryRow(ctx, `
INSERT INTO search_queries (query_text, query_kind, query_vec, top_k, result_keys, session_id, latency_ms)
VALUES ($1, $2, $3::vector, $4, $5::text[], nullif($6, ''), $7)
RETURNING query_id
`, queryText, queryKind, vec, topK, resultKeys, sessionID, latencyMS).Scan(&queryID)
	return queryID, err
}
