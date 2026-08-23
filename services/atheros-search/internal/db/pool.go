package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	expectedDatabase = "sync"
	expectedSchema   = "atheros_search"
)

type Options struct {
	DSN                  string
	TLSCAFile            string
	TLSCertFile          string
	TLSKeyFile           string
	TLSServerName        string
	SchemaManifestSHA256 string
	MaxOpenConns         int
	MaxIdleConns         int
	ConnMaxLifetime      time.Duration
	ConnMaxIdleTime      time.Duration
}

type Pool struct {
	*sql.DB
	expectedManifest string
}

type SchemaReadyStatus struct {
	Ready          bool
	VectorReady    bool
	ManifestSHA256 string
	ExpectedSHA256 string
}

type EmbeddingCounts struct {
	Event     int64
	Device    int64
	Behaviour int64
	Sequence  int64
}

func (c EmbeddingCounts) EmptyKinds() []string {
	empty := make([]string, 0, 4)
	if c.Event == 0 {
		empty = append(empty, "event")
	}
	if c.Device == 0 {
		empty = append(empty, "device")
	}
	if c.Behaviour == 0 {
		empty = append(empty, "behaviour_window")
	}
	if c.Sequence == 0 {
		empty = append(empty, "frame_sequence")
	}
	return empty
}

func NewPool(ctx context.Context, opts Options) (*Pool, error) {
	driverConfig, err := pgx.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse Postgres DSN: %w", err)
	}
	if err := validateDriverConfig(driverConfig); err != nil {
		return nil, err
	}
	if err := configureTLS(driverConfig, opts); err != nil {
		return nil, err
	}
	driverConfig.RuntimeParams["search_path"] = expectedSchema
	driverConfig.RuntimeParams["timezone"] = "UTC"
	driverConfig.RuntimeParams["application_name"] = "atheros-search"
	sqlDB := stdlib.OpenDB(*driverConfig)
	sqlDB.SetMaxOpenConns(opts.MaxOpenConns)
	sqlDB.SetMaxIdleConns(opts.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(opts.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(opts.ConnMaxIdleTime)

	pool := &Pool{DB: sqlDB, expectedManifest: strings.ToLower(opts.SchemaManifestSHA256)}
	if err := pool.Health(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return pool, nil
}

func validateDriverConfig(cfg *pgx.ConnConfig) error {
	trimmedHost := strings.Trim(strings.ToLower(cfg.Host), "[]")
	if trimmedHost == "" || trimmedHost == "localhost" {
		return errors.New("ATHSEARCH_POSTGRES_DSN must use an external non-loopback host")
	}
	if ip := net.ParseIP(trimmedHost); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return errors.New("ATHSEARCH_POSTGRES_DSN must use an external non-loopback host")
	}
	if strings.TrimSpace(cfg.User) == "" || strings.EqualFold(cfg.User, "postgres") || strings.EqualFold(cfg.User, "root") {
		return errors.New("ATHSEARCH_POSTGRES_DSN must use a dedicated non-superuser role")
	}
	if cfg.Password == "" {
		return errors.New("ATHSEARCH_POSTGRES_DSN must include a non-empty credential")
	}
	if cfg.Database != expectedDatabase {
		return fmt.Errorf("ATHSEARCH_POSTGRES_DSN must select database %q", expectedDatabase)
	}
	return nil
}

func configureTLS(cfg *pgx.ConnConfig, opts Options) error {
	if strings.TrimSpace(opts.TLSCAFile) == "" {
		if opts.TLSCertFile != "" || opts.TLSKeyFile != "" || opts.TLSServerName != "" {
			return errors.New("Postgres TLS CA file is required when TLS settings are configured")
		}
		return nil
	}
	caPEM, err := os.ReadFile(opts.TLSCAFile)
	if err != nil {
		return fmt.Errorf("read Postgres CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("Postgres CA file contains no valid certificates")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: strings.TrimSpace(opts.TLSServerName),
	}
	if tlsConfig.ServerName == "" {
		return errors.New("Postgres TLS server name is required")
	}
	if opts.TLSCertFile != "" || opts.TLSKeyFile != "" {
		if opts.TLSCertFile == "" || opts.TLSKeyFile == "" {
			return errors.New("Postgres client certificate and key must be configured together")
		}
		certificate, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load Postgres client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	cfg.TLSConfig = tlsConfig
	return nil
}

func (p *Pool) Health(ctx context.Context) error {
	if p == nil || p.DB == nil {
		return errors.New("Postgres pool is not initialized")
	}
	if err := p.PingContext(ctx); err != nil {
		return fmt.Errorf("Postgres ping: %w", err)
	}

	var databaseName, schemaName, timeZone string
	var versionNum int
	if err := p.QueryRowContext(ctx, "SELECT current_database(), current_schema(), current_setting('TimeZone'), current_setting('server_version_num')::int").Scan(&databaseName, &schemaName, &timeZone, &versionNum); err != nil {
		return fmt.Errorf("Postgres session health query: %w", err)
	}
	if databaseName != expectedDatabase {
		return fmt.Errorf("Postgres selected database %q, expected %q", databaseName, expectedDatabase)
	}
	if schemaName != expectedSchema {
		return fmt.Errorf("Postgres selected schema %q, expected %q", schemaName, expectedSchema)
	}
	if !strings.EqualFold(timeZone, "UTC") && !strings.EqualFold(timeZone, "Etc/UTC") {
		return fmt.Errorf("Postgres session time_zone is %q, expected UTC", timeZone)
	}
	if err := validatePostgresVersion(versionNum); err != nil {
		return err
	}
	return nil
}

func validatePostgresVersion(versionNum int) error {
	if versionNum < 160000 {
		return fmt.Errorf("PostgreSQL 16 or newer is required, got server_version_num %d", versionNum)
	}
	return nil
}

func (p *Pool) SchemaReady(ctx context.Context) (SchemaReadyStatus, error) {
	status := SchemaReadyStatus{ExpectedSHA256: p.expectedManifest}
	var ready, vectorReady bool
	err := p.QueryRowContext(ctx, `
SELECT manifest_sha256, schema_ready, vector_ready
FROM atheros_search.schema_manifest
WHERE component = 'atheros-search'
LIMIT 1
`).Scan(&status.ManifestSHA256, &ready, &vectorReady)
	if err != nil {
		return SchemaReadyStatus{}, fmt.Errorf("Postgres schema readiness query: %w", err)
	}
	status.ManifestSHA256 = strings.ToLower(status.ManifestSHA256)
	status.VectorReady = vectorReady
	status.Ready = ready && vectorReady && status.ManifestSHA256 == status.ExpectedSHA256
	return status, nil
}

func (p *Pool) CountEmbeddings(ctx context.Context) (EmbeddingCounts, error) {
	var counts EmbeddingCounts
	err := p.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM atheros_search.search_vectors_event),
  (SELECT COUNT(*) FROM atheros_search.search_vectors_device),
  (SELECT COUNT(*) FROM atheros_search.search_vectors_behaviour),
  (SELECT COUNT(*) FROM atheros_search.search_vectors_sequence)
`).Scan(&counts.Event, &counts.Device, &counts.Behaviour, &counts.Sequence)
	return counts, err
}

func (p *Pool) PendingJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'pending'
`).Scan(&count)
	return count, err
}

func (p *Pool) FailedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'failed'
`).Scan(&count)
	return count, err
}

func (p *Pool) LeasedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'leased'
`).Scan(&count)
	return count, err
}

func (p *Pool) CompletedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM atheros_search.embedding_jobs WHERE status = 'completed'
`).Scan(&count)
	return count, err
}

func (p *Pool) WorkerHeartbeats(ctx context.Context) ([]WorkerHeartbeatRow, error) {
	rows, err := p.QueryContext(ctx, `
SELECT worker_id, worker_type, last_seen_at, metadata
FROM atheros_search.worker_heartbeat
ORDER BY worker_id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []WorkerHeartbeatRow
	for rows.Next() {
		var r WorkerHeartbeatRow
		if err := rows.Scan(&r.WorkerID, &r.WorkerType, &r.LastSeenAt, &r.Metadata); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

type WorkerHeartbeatRow struct {
	WorkerID   string
	WorkerType string
	LastSeenAt time.Time
	Metadata   []byte
}
