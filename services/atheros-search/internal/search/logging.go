package search

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func LogQuery(ctx context.Context, pool *pgxpool.Pool, queryText, queryKind string, qvec []float32, topK int, resultKeys []string, sessionID string, latencyMS int64) (int64, error) {
	var queryID int64
	var vec any
	if len(qvec) > 0 {
		vec = VectorLiteral(qvec)
	}
	resultKeyHashes := make([]string, 0, len(resultKeys))
	for _, key := range resultKeys {
		key = strings.TrimSpace(key)
		if key != "" {
			resultKeyHashes = append(resultKeyHashes, sha256Hex(key))
		}
	}
	var sessionHash any
	if sessionID = strings.TrimSpace(sessionID); sessionID != "" {
		sessionHash = sha256Hex(sessionID)
	}
	err := pool.QueryRow(ctx, `
INSERT INTO search_queries (hashed_query_text, query_kind, query_vec, top_k, result_key_hashes, session_hash, latency_ms)
VALUES ($1, $2, $3::vector, $4, $5::text[], $6, $7)
RETURNING query_id
`, sha256Hex(queryText), queryKind, vec, topK, resultKeyHashes, sessionHash, latencyMS).Scan(&queryID)
	return queryID, err
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
