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
	var vector any
	if len(qvec) > 0 {
		if err := validateVector(qvec); err != nil {
			return 0, err
		}
		vector = VectorLiteral(qvec)
	}
	queryUUID, err := newUUID()
	if err != nil {
		return 0, err
	}
	var sessionHash any
	if sessionID = strings.TrimSpace(sessionID); sessionID != "" {
		sessionHash = sha256Hex(sessionID)
	}

	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
INSERT INTO search_queries (
  query_uuid, hashed_query_text, query_kind, query_vector,
  top_k, session_hash, latency_ms, created_at, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))
`, queryUUID, sha256Hex(queryText), queryKind, vector, topK, sessionHash, latencyMS)
	if err != nil {
		return 0, err
	}
	queryID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	for ordinal, key := range resultKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO search_query_results (query_id, ordinal, result_key_hash)
VALUES (?, ?, ?)
`, queryID, ordinal+1, sha256Hex(key)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
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
