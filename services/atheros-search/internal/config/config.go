package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	DefaultAuditTopic          = "wireless.audit"
	DefaultBandwidthTopic      = "audit.wireless.bandwidth"
	DefaultCORSAllowedOrigin   = "http://127.0.0.1:5173"
)

type Config struct {
	PostgresDSN             string
	RedpandaBootstrap       string
	EmbeddingModel          string
	EmbeddingDimensions     int
	EmbeddingBackend        string
	EventEmbeddingScope     string
	GRPCPort                int
	HTTPPort                int
	MetricsPort             int
	LogLevel                string
	AuditTopic              string
	BandwidthTopic          string
	ConsumerGroup           string
	SearchTimeout           time.Duration
	HybridAlpha             float64
	APIKeySHA256            string
	EmbedderEnabled         bool
	IngestEnabled           bool
	EmbeddingBatchSize      int
	EmbeddingPollInterval   time.Duration
	ReadyLagThreshold       int64
	SchemaReadyRequired     bool
	SchemaReadyTimeout      time.Duration
	SchemaReadyPollInterval time.Duration
	CORSAllowedOrigins      []string

	WorkerEnabled               bool
	WorkerName                  string
	WorkerBatchSize             int
	WorkerRequestBatchSize      int
	WorkerRequestBatchMax       int
	WorkerLeaseSeconds          int
	WorkerPollInterval          time.Duration
	WorkerMaxDrainBatches       int
	WorkerMaxInputTokens        int
	WorkerDBCallTimeout         time.Duration
	WorkerMaxConcurrentEmbed    int
	WorkerMaxConcurrentComplete int

	AlertEnabled            bool
	AlertSweepInterval      int
	AlertNearDupThreshold   int64
	AlertAPRiskThreshold    float64
	AlertGraphMaxDepth      int
	AlertSeqThreshold       float64
	AlertTravelMaxSpeedMPS  float64
	AlertDNSLookbackMinutes int
}

func Load() (Config, error) {
	env := viper.New()
	env.AutomaticEnv()
	workerBatchSize := envInt("ATHSEARCH_WORKER_BATCH_SIZE", 64)
	workerRequestBatchMax := envInt("ATHSEARCH_WORKER_REQUEST_BATCH_MAX", 128)
	workerRequestBatchSize := envInt("ATHSEARCH_WORKER_REQUEST_BATCH_SIZE", minInt(workerBatchSize, workerRequestBatchMax))
	if err := validateWorkerBatchSettings(workerBatchSize, workerRequestBatchMax, workerRequestBatchSize); err != nil {
		return Config{}, err
	}
	cfg := Config{
		PostgresDSN:                 firstEnv("ATHSEARCH_POSTGRES_DSN", "DATABASE_URL", "SYNC_DATABASE_URL"),
		RedpandaBootstrap:           firstEnv("ATHSEARCH_REDPANDA_BOOTSTRAP", "SYNC_REDPANDA_BOOTSTRAP_SERVERS"),
		EmbeddingModel:              envString("ATHSEARCH_EMBEDDING_MODEL", envString("VECTOR_EMBEDDING_MODEL", DefaultEmbeddingModel)),
		EmbeddingDimensions:         envInt("ATHSEARCH_EMBEDDING_DIMENSIONS", envInt("VECTOR_EMBEDDING_DIMENSIONS", DefaultEmbeddingDimensions)),
		EmbeddingBackend:            firstEnv("ATHSEARCH_EMBEDDING_BACKEND", "VECTOR_EMBEDDING_URL"),
		EventEmbeddingScope:         envString("ATHSEARCH_EVENT_EMBEDDING_SCOPE", "high_signal"),
		GRPCPort:                    envInt("ATHSEARCH_GRPC_PORT", 50051),
		HTTPPort:                    envInt("ATHSEARCH_HTTP_PORT", 8080),
		MetricsPort:                 envInt("ATHSEARCH_METRICS_PORT", 9090),
		LogLevel:                    envStringViper(env, "ATHSEARCH_LOG_LEVEL", "info"),
		AuditTopic:                  envString("ATHSEARCH_AUDIT_TOPIC", DefaultAuditTopic),
		BandwidthTopic:              envString("ATHSEARCH_BANDWIDTH_TOPIC", DefaultBandwidthTopic),
		ConsumerGroup:               envString("ATHSEARCH_CONSUMER_GROUP", "atheros-search-ingest"),
		SearchTimeout:               time.Duration(envInt("ATHSEARCH_SEARCH_TIMEOUT_MS", 10000)) * time.Millisecond,
		HybridAlpha:                 envFloat("ATHSEARCH_HYBRID_ALPHA", 0.5),
		APIKeySHA256:                strings.ToLower(strings.TrimSpace(os.Getenv("ATHSEARCH_API_TOKEN_SHA256"))),
		EmbedderEnabled:             envBool("ATHSEARCH_EMBEDDER_ENABLED", false),
		IngestEnabled:               envBool("ATHSEARCH_INGEST_ENABLED", false),
		EmbeddingBatchSize:          envInt("ATHSEARCH_EMBEDDING_BATCH_SIZE", 32),
		EmbeddingPollInterval:       time.Duration(envInt("ATHSEARCH_EMBEDDING_POLL_INTERVAL_MS", 500)) * time.Millisecond,
		ReadyLagThreshold:           int64(envInt("ATHSEARCH_READY_LAG_THRESHOLD", 10000)),
		SchemaReadyRequired:         envBool("ATHSEARCH_SCHEMA_READY_REQUIRED", true),
		SchemaReadyTimeout:          time.Duration(envInt("ATHSEARCH_SCHEMA_READY_TIMEOUT_MS", 60000)) * time.Millisecond,
		SchemaReadyPollInterval:     time.Duration(envInt("ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS", 1000)) * time.Millisecond,
		CORSAllowedOrigins:          envCSV("ATHSEARCH_CORS_ALLOWED_ORIGINS", []string{DefaultCORSAllowedOrigin}),
		WorkerEnabled:               envBool("ATHSEARCH_WORKER_ENABLED", false),
		WorkerName:                  envString("ATHSEARCH_WORKER_NAME", defaultWorkerName()),
		WorkerBatchSize:             workerBatchSize,
		WorkerRequestBatchSize:      workerRequestBatchSize,
		WorkerRequestBatchMax:       workerRequestBatchMax,
		WorkerLeaseSeconds:          envInt("ATHSEARCH_WORKER_LEASE_SECONDS", 1800),
		WorkerPollInterval:          time.Duration(envInt("ATHSEARCH_WORKER_POLL_INTERVAL_MS", 5000)) * time.Millisecond,
		WorkerMaxDrainBatches:       envInt("ATHSEARCH_WORKER_MAX_DRAIN_BATCHES", 0),
		WorkerMaxInputTokens:        envInt("ATHSEARCH_WORKER_MAX_INPUT_TOKENS", 512),
		WorkerDBCallTimeout:         time.Duration(envInt("ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS", 30000)) * time.Millisecond,
		WorkerMaxConcurrentEmbed:    envInt("ATHSEARCH_WORKER_MAX_CONCURRENT_EMBED", 4),
		WorkerMaxConcurrentComplete: envInt("ATHSEARCH_WORKER_MAX_CONCURRENT_COMPLETE", 16),
		AlertEnabled:                envBool("ATHSEARCH_ALERT_ENABLED", false),
		AlertSweepInterval:          envInt("ATHSEARCH_ALERT_SWEEP_INTERVAL", 10),
		AlertNearDupThreshold:       int64(envInt("ATHSEARCH_ALERT_NEAR_DUP_THRESHOLD", 10)),
		AlertAPRiskThreshold:        envFloat("ATHSEARCH_ALERT_AP_RISK_THRESHOLD", 0.75),
		AlertGraphMaxDepth:          envInt("ATHSEARCH_ALERT_GRAPH_MAX_DEPTH", 3),
		AlertSeqThreshold:           envFloat("ATHSEARCH_ALERT_SEQ_THRESHOLD", -15.0),
		AlertTravelMaxSpeedMPS:      envFloat("ATHSEARCH_ALERT_TRAVEL_MAX_SPEED_MPS", 50.0),
		AlertDNSLookbackMinutes:     envInt("ATHSEARCH_ALERT_DNS_LOOKBACK_MINUTES", 15),
	}

	if cfg.PostgresDSN == "" {
		return cfg, errors.New("ATHSEARCH_POSTGRES_DSN or DATABASE_URL is required")
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
	if cfg.EmbeddingBackend != "" {
		if _, err := url.ParseRequestURI(cfg.EmbeddingBackend); err != nil {
			return cfg, fmt.Errorf("ATHSEARCH_EMBEDDING_BACKEND must be a valid URL: %w", err)
		}
	}
	cfg.EventEmbeddingScope = strings.ToLower(strings.TrimSpace(cfg.EventEmbeddingScope))
	if cfg.EventEmbeddingScope != "high_signal" && cfg.EventEmbeddingScope != "all" {
		return cfg, errors.New("ATHSEARCH_EVENT_EMBEDDING_SCOPE must be high_signal or all")
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
	if cfg.EmbeddingBatchSize < 1 || cfg.EmbeddingBatchSize > 512 {
		return cfg, errors.New("ATHSEARCH_EMBEDDING_BATCH_SIZE must be between 1 and 512")
	}
	if cfg.WorkerMaxInputTokens < 1 {
		return cfg, errors.New("ATHSEARCH_WORKER_MAX_INPUT_TOKENS must be >= 1")
	}
	if cfg.WorkerDBCallTimeout <= 0 {
		return cfg, errors.New("ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS must be positive")
	}
	return cfg, nil
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

func defaultWorkerName() string {
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return strings.TrimSpace(hostname)
	}
	return "atheros-search-worker"
}

func validateWorkerBatchSettings(workerBatchSize, workerRequestBatchMax, workerRequestBatchSize int) error {
	if workerBatchSize < 1 || workerBatchSize > 1024 {
		return errors.New("ATHSEARCH_WORKER_BATCH_SIZE must be 1-1024")
	}
	if workerRequestBatchMax < 1 {
		return errors.New("ATHSEARCH_WORKER_REQUEST_BATCH_MAX must be >= 1")
	}
	if workerRequestBatchSize < 1 {
		return errors.New("ATHSEARCH_WORKER_REQUEST_BATCH_SIZE must be >= 1")
	}
	if workerRequestBatchSize > workerRequestBatchMax {
		return errors.New("ATHSEARCH_WORKER_REQUEST_BATCH_SIZE must be <= ATHSEARCH_WORKER_REQUEST_BATCH_MAX")
	}
	if workerRequestBatchSize > workerBatchSize {
		return errors.New("ATHSEARCH_WORKER_REQUEST_BATCH_SIZE must be <= ATHSEARCH_WORKER_BATCH_SIZE")
	}
	return nil
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
