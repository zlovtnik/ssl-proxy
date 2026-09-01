package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	DefaultEmbeddingModel      = "nomic-embed-text-v2-moe"
	DefaultEmbeddingDimensions = 768
	DefaultCORSAllowedOrigin   = "http://127.0.0.1:5173"
)

type Config struct {
	PostgresDSN                  string
	PostgresTLSCAFile            string
	PostgresTLSCertFile          string
	PostgresTLSKeyFile           string
	PostgresTLSServerName        string
	PostgresSchemaManifestSHA256 string
	PostgresMaxOpenConns         int
	PostgresMaxIdleConns         int
	PostgresConnMaxLifetime      time.Duration
	PostgresConnMaxIdleTime      time.Duration
	EmbeddingModel               string
	EmbeddingDimensions          int
	EmbeddingBackend             string
	GRPCPort                     int
	HTTPPort                     int
	MetricsPort                  int
	LogLevel                     string
	SearchTimeout                time.Duration
	HybridAlpha                  float64
	DenseOverfetchFactor         int
	APIKeySHA256                 string
	JWTIssuer                    string
	JWTJWKSURI                   string
	JWTAudience                  string
	JWTClientID                  string
	SchemaReadyRequired          bool
	SchemaReadyTimeout           time.Duration
	SchemaReadyPollInterval      time.Duration
	CORSAllowedOrigins           []string
	WorkerEnabled                bool
	WorkerCount                  int
	EmbeddingBatchSize           int
	LeaseSeconds                 int
	WorkerPollInterval           time.Duration
	WorkerID                     string
	WSEnabled                    bool
}

func Load() (Config, error) {
	env := viper.New()
	env.AutomaticEnv()
	postgresDSN := strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_DSN"))
	postgresTLSCAFile := strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_TLS_CA_FILE"))
	if postgresDSN == "" {
		postgresHost := strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_HOST"))
		postgresPort := envInt("ATHSEARCH_POSTGRES_PORT", 5432)
		postgresDatabase := envString("ATHSEARCH_POSTGRES_DATABASE", "sync")
		postgresUser := envString("ATHSEARCH_POSTGRES_USER", "atheros_search_runtime")
		postgresPassword, err := secretValue(
			"ATHSEARCH_POSTGRES_PASSWORD",
			"ATHSEARCH_POSTGRES_PASSWORD_FILE",
			os.ReadFile,
		)
		if err != nil {
			return Config{}, err
		}
		if postgresHost == "" {
			return Config{}, errors.New("ATHSEARCH_POSTGRES_HOST is required when ATHSEARCH_POSTGRES_DSN is not set")
		}
		if postgresPort < 1 || postgresPort > 65535 {
			return Config{}, errors.New("ATHSEARCH_POSTGRES_PORT must be between 1 and 65535")
		}
		if strings.TrimSpace(postgresPassword) == "" {
			return Config{}, errors.New("ATHSEARCH_POSTGRES_PASSWORD is required when ATHSEARCH_POSTGRES_DSN is not set")
		}
		connectionURL := &url.URL{
			Scheme: "postgresql",
			User:   url.UserPassword(postgresUser, postgresPassword),
			Host:   net.JoinHostPort(strings.Trim(postgresHost, "[]"), strconv.Itoa(postgresPort)),
			Path:   "/" + postgresDatabase,
		}
		query := connectionURL.Query()
		if postgresTLSCAFile != "" {
			query.Set("sslmode", "verify-full")
		} else {
			query.Set("sslmode", "disable")
		}
		connectionURL.RawQuery = query.Encode()
		postgresDSN = connectionURL.String()
	}
	cfg := Config{
		PostgresDSN:                  postgresDSN,
		PostgresTLSCAFile:            postgresTLSCAFile,
		PostgresTLSCertFile:          strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_TLS_CERT_FILE")),
		PostgresTLSKeyFile:           strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_TLS_KEY_FILE")),
		PostgresTLSServerName:        strings.TrimSpace(os.Getenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME")),
		PostgresSchemaManifestSHA256: strings.ToLower(strings.TrimSpace(os.Getenv("ATHSEARCH_SCHEMA_MANIFEST_SHA256"))),
		PostgresMaxOpenConns:         envInt("ATHSEARCH_POSTGRES_MAX_OPEN_CONNS", 32),
		PostgresMaxIdleConns:         envInt("ATHSEARCH_POSTGRES_MAX_IDLE_CONNS", 8),
		PostgresConnMaxLifetime:      time.Duration(envInt("ATHSEARCH_POSTGRES_CONN_MAX_LIFETIME_MS", 300000)) * time.Millisecond,
		PostgresConnMaxIdleTime:      time.Duration(envInt("ATHSEARCH_POSTGRES_CONN_MAX_IDLE_TIME_MS", 60000)) * time.Millisecond,
		EmbeddingModel:               envString("ATHSEARCH_EMBEDDING_MODEL", envString("VECTOR_EMBEDDING_MODEL", DefaultEmbeddingModel)),
		EmbeddingDimensions:          envInt("ATHSEARCH_EMBEDDING_DIMENSIONS", envInt("VECTOR_EMBEDDING_DIMENSIONS", DefaultEmbeddingDimensions)),
		EmbeddingBackend:             firstEnv("ATHSEARCH_EMBEDDING_BACKEND", "VECTOR_EMBEDDING_URL"),
		GRPCPort:                     envInt("ATHSEARCH_GRPC_PORT", 50051),
		HTTPPort:                     envInt("ATHSEARCH_HTTP_PORT", 8080),
		MetricsPort:                  envInt("ATHSEARCH_METRICS_PORT", 9090),
		LogLevel:                     envStringViper(env, "ATHSEARCH_LOG_LEVEL", "info"),
		SearchTimeout:                time.Duration(envInt("ATHSEARCH_SEARCH_TIMEOUT_MS", 10000)) * time.Millisecond,
		HybridAlpha:                  envFloat("ATHSEARCH_HYBRID_ALPHA", 0.5),
		DenseOverfetchFactor:         envInt("ATHSEARCH_DENSE_OVERFETCH_FACTOR", 8),
		APIKeySHA256:                 strings.ToLower(strings.TrimSpace(os.Getenv("ATHSEARCH_API_TOKEN_SHA256"))),
		JWTIssuer:                    strings.TrimSpace(os.Getenv("ATHSEARCH_JWT_ISSUER")),
		JWTJWKSURI:                   strings.TrimSpace(os.Getenv("ATHSEARCH_JWT_JWKS_URI")),
		JWTAudience:                  strings.TrimSpace(os.Getenv("ATHSEARCH_JWT_AUDIENCE")),
		JWTClientID:                  strings.TrimSpace(os.Getenv("ATHSEARCH_JWT_CLIENT_ID")),
		SchemaReadyRequired:          envBool("ATHSEARCH_SCHEMA_READY_REQUIRED", true),
		SchemaReadyTimeout:           time.Duration(envInt("ATHSEARCH_SCHEMA_READY_TIMEOUT_MS", 60000)) * time.Millisecond,
		SchemaReadyPollInterval:      time.Duration(envInt("ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS", 1000)) * time.Millisecond,
		CORSAllowedOrigins:           envCSV("ATHSEARCH_CORS_ALLOWED_ORIGINS", []string{DefaultCORSAllowedOrigin}),
		WorkerEnabled:                envBool("ATHSEARCH_WORKER_ENABLED", false),
		WorkerCount:                  envInt("ATHSEARCH_WORKER_COUNT", 4),
		EmbeddingBatchSize:           envInt("ATHSEARCH_EMBEDDING_BATCH_SIZE", 64),
		LeaseSeconds:                 envInt("ATHSEARCH_LEASE_SECONDS", 1800),
		WorkerPollInterval:           time.Duration(envInt("ATHSEARCH_POLL_INTERVAL_MS", 1000)) * time.Millisecond,
		WorkerID:                     envString("ATHSEARCH_WORKER_ID", "worker-1"),
		WSEnabled:                    envBool("ATHSEARCH_WS_ENABLED", false),
	}

	if cfg.WorkerEnabled {
		if cfg.EmbeddingBackend == "" {
			return cfg, errors.New("ATHSEARCH_EMBEDDING_BACKEND is required when workers are enabled")
		}
		if cfg.WorkerCount <= 0 {
			return cfg, errors.New("ATHSEARCH_WORKER_COUNT must be positive when workers are enabled")
		}
		if cfg.EmbeddingBatchSize <= 0 {
			return cfg, errors.New("ATHSEARCH_EMBEDDING_BATCH_SIZE must be positive when workers are enabled")
		}
		if cfg.LeaseSeconds <= 0 {
			return cfg, errors.New("ATHSEARCH_LEASE_SECONDS must be positive when workers are enabled")
		}
		if cfg.WorkerPollInterval <= 0 {
			return cfg, errors.New("ATHSEARCH_POLL_INTERVAL_MS must be positive when workers are enabled")
		}
	}
	if !strings.HasPrefix(cfg.PostgresDSN, "postgres://") && !strings.HasPrefix(cfg.PostgresDSN, "postgresql://") {
		return cfg, errors.New("ATHSEARCH_POSTGRES_DSN must be a PostgreSQL connection URL")
	}
	if (cfg.PostgresTLSCertFile == "") != (cfg.PostgresTLSKeyFile == "") {
		return cfg, errors.New("ATHSEARCH_POSTGRES_TLS_CERT_FILE and ATHSEARCH_POSTGRES_TLS_KEY_FILE must be configured together")
	}
	if cfg.PostgresTLSCAFile == "" && (cfg.PostgresTLSCertFile != "" || cfg.PostgresTLSKeyFile != "" || cfg.PostgresTLSServerName != "") {
		return cfg, errors.New("ATHSEARCH_POSTGRES_TLS_CA_FILE is required when any Postgres TLS setting is configured")
	}
	if cfg.PostgresTLSCAFile != "" && cfg.PostgresTLSServerName == "" {
		return cfg, errors.New("ATHSEARCH_POSTGRES_TLS_SERVER_NAME is required")
	}
	if cfg.PostgresTLSCAFile != "" {
		parsedDSN, err := url.Parse(cfg.PostgresDSN)
		if err != nil || parsedDSN.Query().Get("sslmode") != "verify-full" {
			return cfg, errors.New("ATHSEARCH_POSTGRES_DSN must set sslmode=verify-full when Postgres TLS is configured")
		}
	}
	if len(cfg.PostgresSchemaManifestSHA256) != sha256.Size*2 {
		return cfg, errors.New("ATHSEARCH_SCHEMA_MANIFEST_SHA256 must be a 64-character hex SHA-256 digest")
	}
	if _, err := hex.DecodeString(cfg.PostgresSchemaManifestSHA256); err != nil {
		return cfg, errors.New("ATHSEARCH_SCHEMA_MANIFEST_SHA256 must be a 64-character hex SHA-256 digest")
	}
	if cfg.PostgresMaxOpenConns < 1 || cfg.PostgresMaxOpenConns > 512 {
		return cfg, errors.New("ATHSEARCH_POSTGRES_MAX_OPEN_CONNS must be between 1 and 512")
	}
	if cfg.PostgresMaxIdleConns < 0 || cfg.PostgresMaxIdleConns > cfg.PostgresMaxOpenConns {
		return cfg, errors.New("ATHSEARCH_POSTGRES_MAX_IDLE_CONNS must be between 0 and ATHSEARCH_POSTGRES_MAX_OPEN_CONNS")
	}
	if cfg.PostgresConnMaxLifetime <= 0 || cfg.PostgresConnMaxIdleTime <= 0 {
		return cfg, errors.New("Postgres connection lifetime and idle time must be positive")
	}
	if cfg.EmbeddingDimensions != DefaultEmbeddingDimensions {
		return cfg, fmt.Errorf("ATHSEARCH_EMBEDDING_DIMENSIONS must be %d, got %d", DefaultEmbeddingDimensions, cfg.EmbeddingDimensions)
	}
	if cfg.HybridAlpha < 0 || cfg.HybridAlpha > 1 {
		return cfg, fmt.Errorf("ATHSEARCH_HYBRID_ALPHA must be between 0 and 1, got %f", cfg.HybridAlpha)
	}
	if cfg.APIKeySHA256 != "" {
		if _, err := hex.DecodeString(cfg.APIKeySHA256); err != nil || len(cfg.APIKeySHA256) != sha256.Size*2 {
			return cfg, errors.New("ATHSEARCH_API_TOKEN_SHA256 must be a 64-character hex SHA-256 digest")
		}
	}
	jwtSettings := []string{cfg.JWTIssuer, cfg.JWTJWKSURI, cfg.JWTAudience, cfg.JWTClientID}
	jwtConfigured := 0
	for _, value := range jwtSettings {
		if value != "" {
			jwtConfigured++
		}
	}
	if jwtConfigured != 0 && jwtConfigured != len(jwtSettings) {
		return cfg, errors.New("ATHSEARCH_JWT_ISSUER, ATHSEARCH_JWT_JWKS_URI, ATHSEARCH_JWT_AUDIENCE and ATHSEARCH_JWT_CLIENT_ID must be configured together")
	}
	if cfg.APIKeySHA256 != "" && jwtConfigured != 0 {
		return cfg, errors.New("ATHSEARCH_API_TOKEN_SHA256 cannot be combined with JWT authentication")
	}
	for name, value := range map[string]string{"ATHSEARCH_JWT_ISSUER": cfg.JWTIssuer, "ATHSEARCH_JWT_JWKS_URI": cfg.JWTJWKSURI} {
		if value != "" {
			parsed, err := url.ParseRequestURI(value)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Host))) {
				return cfg, fmt.Errorf("%s must be an absolute HTTPS URL (HTTP allowed for loopback only)", name)
			}
		}
	}
	if cfg.EmbeddingBackend != "" {
		if _, err := url.ParseRequestURI(cfg.EmbeddingBackend); err != nil {
			return cfg, fmt.Errorf("ATHSEARCH_EMBEDDING_BACKEND must be a valid URL: %w", err)
		}
	}
	if cfg.SearchTimeout <= 0 {
		return cfg, errors.New("ATHSEARCH_SEARCH_TIMEOUT_MS must be positive")
	}
	if cfg.SchemaReadyTimeout <= 0 {
		return cfg, errors.New("ATHSEARCH_SCHEMA_READY_TIMEOUT_MS must be positive")
	}
	if cfg.SchemaReadyPollInterval <= 0 {
		return cfg, errors.New("ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS must be positive")
	}
	if cfg.DenseOverfetchFactor < 1 || cfg.DenseOverfetchFactor > 100 {
		return cfg, errors.New("ATHSEARCH_DENSE_OVERFETCH_FACTOR must be between 1 and 100")
	}
	return cfg, nil
}

func secretValue(name, fileName string, readFile func(string) ([]byte, error)) (string, error) {
	value := os.Getenv(name)
	path := strings.TrimSpace(os.Getenv(fileName))
	if value != "" && path != "" {
		return "", fmt.Errorf("%s and %s cannot both be configured", name, fileName)
	}
	if path == "" {
		return value, nil
	}
	contents, err := readFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	contents = bytes.TrimSuffix(contents, []byte("\n"))
	contents = bytes.TrimSuffix(contents, []byte("\r"))
	if len(contents) == 0 || bytes.ContainsAny(contents, "\r\n\x00") {
		return "", fmt.Errorf("%s must contain one non-empty line", fileName)
	}
	return string(contents), nil
}

func ClampTopK(v int32) int {
	if v <= 0 {
		return 10
	}
	if v > 100 {
		return 100
	}
	return int(v)
}

func NormalizeMAC(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func DBKind(kind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "event":
		return "event", true
	case "behaviour", "behavior", "behaviour_window", "behavior_window":
		return "behaviour_window", true
	case "sequence", "frame_sequence":
		return "frame_sequence", true
	case "device":
		return "device", true
	default:
		return "", false
	}
}

func SupportedDBKinds() []string {
	return []string{"event", "behaviour_window", "frame_sequence", "device"}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func isLoopbackHost(host string) bool {
	hostname := strings.Trim(strings.ToLower(host), "[]")
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envStringViper(env *viper.Viper, key, fallback string) string {
	if value := strings.TrimSpace(env.GetString(key)); value != "" {
		return value
	}
	return fallback
}

func envCSV(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
