package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/rs/zerolog"
)

func main() {
	dsn := flag.String("dsn", envOr("ATHSEARCH_TIDB_DSN", ""), "TiDB DSN (required)")
	tlsCA := flag.String("tls-ca", envOr("ATHSEARCH_TIDB_TLS_CA_FILE", ""), "Optional TiDB TLS CA file")
	tlsCert := flag.String("tls-cert", envOr("ATHSEARCH_TIDB_TLS_CERT_FILE", ""), "TiDB TLS cert file")
	tlsKey := flag.String("tls-key", envOr("ATHSEARCH_TIDB_TLS_KEY_FILE", ""), "TiDB TLS key file")
	tlsServer := flag.String("tls-server", envOr("ATHSEARCH_TIDB_TLS_SERVER_NAME", ""), "TiDB TLS server name")
	schemaManifestSHA256 := flag.String("schema-manifest-sha256", envOr("ATHSEARCH_SCHEMA_MANIFEST_SHA256", ""), "Expected schema manifest SHA-256 (required)")
	action := flag.String("action", "status", "Action: status, reset-stale, retry-failed")
	staleMinutes := flag.Int("stale-minutes", 60, "Minutes after which a leased job is considered stale")
	flag.Parse()

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	if *dsn == "" {
		logger.Fatal().Msg("ATHSEARCH_TIDB_DSN is required")
	}
	manifestSHA256 := strings.ToLower(strings.TrimSpace(*schemaManifestSHA256))
	if len(manifestSHA256) != sha256.Size*2 {
		logger.Fatal().Msg("ATHSEARCH_SCHEMA_MANIFEST_SHA256 must be a 64-character hex SHA-256 digest")
	}
	if _, err := hex.DecodeString(manifestSHA256); err != nil {
		logger.Fatal().Msg("ATHSEARCH_SCHEMA_MANIFEST_SHA256 must be a 64-character hex SHA-256 digest")
	}

	db, err := openDB(*dsn, *tlsCA, *tlsCert, *tlsKey, *tlsServer)
	if err != nil {
		logger.Fatal().Err(err).Msg("connect to TiDB")
	}
	defer db.Close()

	ctx := context.Background()

	if err := verifySchemaGate(ctx, db, manifestSHA256, logger); err != nil {
		logger.Fatal().Err(err).Msg("schema readiness verification failed")
	}
	logger.Info().Msg("schema readiness gate passed")

	switch *action {
	case "status":
		err = showStatus(ctx, db, logger)
	case "reset-stale":
		err = resetStaleJobs(ctx, db, logger, time.Duration(*staleMinutes)*time.Minute)
	case "retry-failed":
		err = retryFailedJobs(ctx, db, logger)
	default:
		logger.Fatal().Str("action", *action).Msg("unknown action")
	}

	if err != nil {
		logger.Fatal().Err(err).Str("action", *action).Msg("action failed")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func openDB(dsn, tlsCA, tlsCert, tlsKey, tlsServer string) (*sql.DB, error) {
	driverConfig, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}

	if tlsCA != "" {
		caPEM, err := os.ReadFile(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certs in CA file")
		}
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: tlsServer,
		}
		if tlsCert != "" && tlsKey != "" {
			cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				return nil, fmt.Errorf("load client cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		digest := sha256.Sum256([]byte(tlsCA))
		tlsName := "repair-" + hex.EncodeToString(digest[:8])
		if err := mysql.RegisterTLSConfig(tlsName, tlsCfg); err != nil {
			return nil, err
		}
		driverConfig.TLSConfig = tlsName
	}

	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC

	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func showStatus(ctx context.Context, db *sql.DB, logger zerolog.Logger) error {
	type statusRow struct {
		Status string
		Count  int64
	}
	rows, err := db.QueryContext(ctx, `
SELECT status, COUNT(*) AS count
FROM embedding_jobs
GROUP BY status
ORDER BY status
`)
	if err != nil {
		return err
	}
	defer rows.Close()

	logger.Info().Msg("=== Embedding Job Status ===")
	for rows.Next() {
		var r statusRow
		if err := rows.Scan(&r.Status, &r.Count); err != nil {
			return err
		}
		logger.Info().Str("status", r.Status).Int64("count", r.Count).Msg("")
	}

	var total int64
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM embedding_jobs").Scan(&total)
	logger.Info().Int64("total", total).Msg("")

	var workerCount int64
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM worker_heartbeat").Scan(&workerCount)
	logger.Info().Int64("heartbeat_rows", workerCount).Msg("Worker heartbeats")

	return nil
}

func resetStaleJobs(ctx context.Context, db *sql.DB, logger zerolog.Logger, staleThreshold time.Duration) error {
	result, err := db.ExecContext(ctx, `
UPDATE embedding_jobs
SET status = 'pending',
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    next_attempt_at = NOW(6),
    updated_at = CURRENT_TIMESTAMP(6)
WHERE status = 'leased'
  AND lease_expires_at < ?
`, time.Now().Add(-staleThreshold))
	if err != nil {
		return fmt.Errorf("reset stale jobs: %w", err)
	}
	affected, _ := result.RowsAffected()
	logger.Info().Int64("reset", affected).Dur("stale_threshold", staleThreshold).Msg("stale jobs reset to pending")
	return nil
}

func retryFailedJobs(ctx context.Context, db *sql.DB, logger zerolog.Logger) error {
	result, err := db.ExecContext(ctx, `
UPDATE embedding_jobs
SET status = 'pending',
    owner_id = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    attempt_count = 0,
    next_attempt_at = NOW(6),
    last_error = NULL,
    updated_at = CURRENT_TIMESTAMP(6)
WHERE status = 'failed'
`)
	if err != nil {
		return fmt.Errorf("retry failed jobs: %w", err)
	}
	affected, _ := result.RowsAffected()
	logger.Info().Int64("retried", affected).Msg("failed jobs reset to pending")
	return nil
}

func verifySchemaGate(ctx context.Context, database *sql.DB, expectedSHA256 string, logger zerolog.Logger) error {
	var manifestSHA256 string
	var ready, vectorReady bool
	err := database.QueryRowContext(ctx, `
SELECT manifest_sha256, schema_ready, vector_ready
FROM schema_manifest
WHERE component = 'atheros-search'
LIMIT 1
`).Scan(&manifestSHA256, &ready, &vectorReady)
	if err != nil {
		return fmt.Errorf("schema readiness query: %w", err)
	}
	manifestSHA256 = strings.ToLower(manifestSHA256)
	if manifestSHA256 != expectedSHA256 {
		return fmt.Errorf("schema manifest mismatch: got %s, expected %s", manifestSHA256, expectedSHA256)
	}
	if !ready || !vectorReady {
		return fmt.Errorf("schema not ready: ready=%t vector_ready=%t", ready, vectorReady)
	}
	logger.Info().
		Str("manifest_sha256", manifestSHA256).
		Bool("ready", ready).
		Bool("vector_ready", vectorReady).
		Msg("schema gate passed")
	return nil
}
