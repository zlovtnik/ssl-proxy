package search

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

func LogQuery(ctx context.Context, pool *sql.DB, queryText, queryKind string, qvec []float32, topK int, resultKeys []string, sessionID string, latencyMS int64) (int64, error) {
	_ = qvec
	queryUUID, err := newUUID()
	if err != nil {
		return 0, err
	}
	var sessionHash any
	if sessionID = strings.TrimSpace(sessionID); sessionID != "" {
		sessionHash = sha256Hex(sessionID)
	}

	var queryID int64
	err = pool.QueryRowContext(ctx, `
INSERT INTO atheros_search.search_queries (
  query_uuid, hashed_query_text, query_kind, top_k, session_hash,
  latency_ms, result_count, request_metadata, created_at, expires_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7,
  jsonb_build_object('has_query', $8),
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP + INTERVAL '30 days'
)
RETURNING query_id
`, queryUUID, sha256Hex(queryText), queryKind, topK, sessionHash, latencyMS, len(resultKeys), strings.TrimSpace(queryText) != "").Scan(&queryID)
	if err != nil {
		return 0, err
	}
	return queryID, nil
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
