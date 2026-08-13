package db

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const expectedDatabase = "atheros_search"

var tidbVersionPattern = regexp.MustCompile(`(?i)tidb(?:-|\s+)v?(\d+)\.(\d+)`)

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
	driverConfig, err := mysql.ParseDSN(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse TiDB DSN: %w", err)
	}
	if err := validateDriverConfig(driverConfig); err != nil {
		return nil, err
	}

	tlsName, err := registerTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	driverConfig.TLSConfig = tlsName
	driverConfig.AllowAllFiles = false
	driverConfig.AllowCleartextPasswords = false
	driverConfig.AllowOldPasswords = false
	if driverConfig.Params == nil {
		driverConfig.Params = map[string]string{}
	}
	driverConfig.Params["time_zone"] = "'+00:00'"
	driverConfig.Params["sql_mode"] = "'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"

	sqlDB, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open TiDB pool: %w", err)
	}
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

func validateDriverConfig(cfg *mysql.Config) error {
	if cfg.Net != "tcp" {
		return errors.New("ATHSEARCH_TIDB_DSN must use tcp networking")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return fmt.Errorf("ATHSEARCH_TIDB_DSN must include host and port: %w", err)
	}
	trimmedHost := strings.Trim(strings.ToLower(host), "[]")
	if trimmedHost == "" || trimmedHost == "localhost" {
		return errors.New("ATHSEARCH_TIDB_DSN must use an external non-loopback host")
	}
	if ip := net.ParseIP(trimmedHost); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return errors.New("ATHSEARCH_TIDB_DSN must use an external non-loopback host")
	}
	if strings.EqualFold(strings.TrimSpace(cfg.User), "root") || strings.TrimSpace(cfg.User) == "" {
		return errors.New("ATHSEARCH_TIDB_DSN must use a dedicated non-root user")
	}
	if cfg.Passwd == "" {
		return errors.New("ATHSEARCH_TIDB_DSN must include a non-empty credential")
	}
	if cfg.DBName != expectedDatabase {
		return fmt.Errorf("ATHSEARCH_TIDB_DSN must select database %q", expectedDatabase)
	}
	return nil
}

func registerTLSConfig(opts Options) (string, error) {
	caPEM, err := os.ReadFile(opts.TLSCAFile)
	if err != nil {
		return "", fmt.Errorf("read TiDB CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return "", errors.New("TiDB CA file contains no valid certificates")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: strings.TrimSpace(opts.TLSServerName),
	}
	if tlsConfig.ServerName == "" {
		return "", errors.New("TiDB TLS server name is required")
	}
	if opts.TLSCertFile != "" || opts.TLSKeyFile != "" {
		if opts.TLSCertFile == "" || opts.TLSKeyFile == "" {
			return "", errors.New("TiDB client certificate and key must be configured together")
		}
		certificate, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return "", fmt.Errorf("load TiDB client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	digest := sha256.Sum256([]byte(strings.Join([]string{
		opts.TLSCAFile,
		opts.TLSCertFile,
		opts.TLSKeyFile,
		opts.TLSServerName,
	}, "\x00")))
	name := "athsearch-" + hex.EncodeToString(digest[:8])
	if err := mysql.RegisterTLSConfig(name, tlsConfig); err != nil {
		return "", fmt.Errorf("register TiDB TLS configuration: %w", err)
	}
	return name, nil
}

func (p *Pool) Health(ctx context.Context) error {
	if p == nil || p.DB == nil {
		return errors.New("TiDB pool is not initialized")
	}
	if err := p.PingContext(ctx); err != nil {
		return fmt.Errorf("TiDB ping: %w", err)
	}

	var databaseName, timeZone, sqlMode, version string
	if err := p.QueryRowContext(ctx, "SELECT DATABASE(), @@time_zone, @@sql_mode, VERSION()").Scan(&databaseName, &timeZone, &sqlMode, &version); err != nil {
		return fmt.Errorf("TiDB session health query: %w", err)
	}
	if databaseName != expectedDatabase {
		return fmt.Errorf("TiDB selected database %q, expected %q", databaseName, expectedDatabase)
	}
	if timeZone != "+00:00" && !strings.EqualFold(timeZone, "UTC") {
		return fmt.Errorf("TiDB session time_zone is %q, expected UTC", timeZone)
	}
	if !strings.Contains(strings.ToUpper(sqlMode), "STRICT_ALL_TABLES") && !strings.Contains(strings.ToUpper(sqlMode), "STRICT_TRANS_TABLES") {
		return fmt.Errorf("TiDB session sql_mode is not strict: %q", sqlMode)
	}
	if err := validateTiDBVersion(version); err != nil {
		return err
	}
	return nil
}

func validateTiDBVersion(version string) error {
	match := tidbVersionPattern.FindStringSubmatch(version)
	if len(match) != 3 {
		return fmt.Errorf("database server is not identifiable as TiDB: %q", version)
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	if major < 8 || (major == 8 && minor < 5) {
		return fmt.Errorf("TiDB v8.5 or newer is required, got %q", version)
	}
	return nil
}

func (p *Pool) SchemaReady(ctx context.Context) (SchemaReadyStatus, error) {
	status := SchemaReadyStatus{ExpectedSHA256: p.expectedManifest}
	var ready, vectorReady bool
	err := p.QueryRowContext(ctx, `
SELECT manifest_sha256, schema_ready, vector_ready
FROM schema_manifest
WHERE component = 'atheros-search'
LIMIT 1
`).Scan(&status.ManifestSHA256, &ready, &vectorReady)
	if err != nil {
		return SchemaReadyStatus{}, fmt.Errorf("TiDB schema readiness query: %w", err)
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
  (SELECT COUNT(*) FROM search_vectors_event),
  (SELECT COUNT(*) FROM search_vectors_device),
  (SELECT COUNT(*) FROM search_vectors_behaviour),
  (SELECT COUNT(*) FROM search_vectors_sequence)
`).Scan(&counts.Event, &counts.Device, &counts.Behaviour, &counts.Sequence)
	return counts, err
}

func (p *Pool) PendingJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'pending'
`).Scan(&count)
	return count, err
}

func (p *Pool) FailedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'failed'
`).Scan(&count)
	return count, err
}

func (p *Pool) LeasedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'leased'
`).Scan(&count)
	return count, err
}

func (p *Pool) CompletedJobCount(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRowContext(ctx, `
SELECT COUNT(*) FROM embedding_jobs WHERE status = 'completed'
`).Scan(&count)
	return count, err
}

func (p *Pool) WorkerHeartbeats(ctx context.Context) ([]WorkerHeartbeatRow, error) {
	rows, err := p.QueryContext(ctx, `
SELECT worker_id, worker_type, last_seen_at, metadata
FROM worker_heartbeat
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
