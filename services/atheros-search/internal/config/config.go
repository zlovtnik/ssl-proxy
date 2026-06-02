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
)

type Config struct {
	PostgresDSN           string
	RedpandaBootstrap     string
	EmbeddingModel        string
	EmbeddingDimensions   int
	EmbeddingBackend      string
	GRPCPort              int
	HTTPPort              int
	MetricsPort           int
	LogLevel              string
	AuditTopic            string
	BandwidthTopic        string
	ConsumerGroup         string
	SearchTimeout         time.Duration
	HybridAlpha           float64
	APIKeySHA256          string
	EmbedderEnabled       bool
	IngestEnabled         bool
	EmbeddingBatchSize    int
	EmbeddingPollInterval time.Duration
	ReadyLagThreshold     int64
}

func Load() (Config, error) {
	env := viper.New()
	env.AutomaticEnv()
	cfg := Config{
		PostgresDSN:           firstEnv("ATHSEARCH_POSTGRES_DSN", "DATABASE_URL", "SYNC_DATABASE_URL"),
		RedpandaBootstrap:     firstEnv("ATHSEARCH_REDPANDA_BOOTSTRAP", "SYNC_REDPANDA_BOOTSTRAP_SERVERS"),
		EmbeddingModel:        envString("ATHSEARCH_EMBEDDING_MODEL", envString("VECTOR_EMBEDDING_MODEL", DefaultEmbeddingModel)),
		EmbeddingDimensions:   envInt("ATHSEARCH_EMBEDDING_DIMENSIONS", envInt("VECTOR_EMBEDDING_DIMENSIONS", DefaultEmbeddingDimensions)),
		EmbeddingBackend:      firstEnv("ATHSEARCH_EMBEDDING_BACKEND", "VECTOR_EMBEDDING_URL"),
		GRPCPort:              envInt("ATHSEARCH_GRPC_PORT", 50051),
		HTTPPort:              envInt("ATHSEARCH_HTTP_PORT", 8080),
		MetricsPort:           envInt("ATHSEARCH_METRICS_PORT", 9090),
		LogLevel:              envStringViper(env, "ATHSEARCH_LOG_LEVEL", "info"),
		AuditTopic:            envString("ATHSEARCH_AUDIT_TOPIC", DefaultAuditTopic),
		BandwidthTopic:        envString("ATHSEARCH_BANDWIDTH_TOPIC", DefaultBandwidthTopic),
		ConsumerGroup:         envString("ATHSEARCH_CONSUMER_GROUP", "atheros-search-ingest"),
		SearchTimeout:         time.Duration(envInt("ATHSEARCH_SEARCH_TIMEOUT_MS", 750)) * time.Millisecond,
		HybridAlpha:           envFloat("ATHSEARCH_HYBRID_ALPHA", 0.5),
		APIKeySHA256:          strings.ToLower(strings.TrimSpace(os.Getenv("ATHSEARCH_API_TOKEN_SHA256"))),
		EmbedderEnabled:       envBool("ATHSEARCH_EMBEDDER_ENABLED", false),
		IngestEnabled:         envBool("ATHSEARCH_INGEST_ENABLED", false),
		EmbeddingBatchSize:    envInt("ATHSEARCH_EMBEDDING_BATCH_SIZE", 32),
		EmbeddingPollInterval: time.Duration(envInt("ATHSEARCH_EMBEDDING_POLL_INTERVAL_MS", 500)) * time.Millisecond,
		ReadyLagThreshold:     int64(envInt("ATHSEARCH_READY_LAG_THRESHOLD", 10000)),
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
	if cfg.SearchTimeout <= 0 {
		return cfg, errors.New("ATHSEARCH_SEARCH_TIMEOUT_MS must be positive")
	}
	if cfg.EmbeddingBatchSize < 1 || cfg.EmbeddingBatchSize > 512 {
		return cfg, errors.New("ATHSEARCH_EMBEDDING_BATCH_SIZE must be between 1 and 512")
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
