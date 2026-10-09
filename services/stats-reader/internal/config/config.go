// Package config loads stats-reader settings from the environment.
package config

import (
	"os"
	"strconv"
	"strings"
)

const (
	DefaultHTTPPort         = 8080
	DefaultRedisAddr        = "ssl-proxy-redis-runtime:6379"
	DefaultRedisKey         = "stats:current:v2"
	DefaultMinioEndpoint    = "ssl-proxy-minio-api:9000"
	DefaultMinioStatsBucket = "ssl-proxy-stats"
	DefaultMinioStatsPrefix = "stats/"
)

// DefaultAllowedOrigins is the CORS allowlist used when
// STATS_ALLOWED_ORIGINS is unset.
var DefaultAllowedOrigins = []string{"https://rclabs.uk", "https://www.rclabs.uk"}

// Config holds process settings. Store hostnames stay in config and are
// never echoed in response bodies.
type Config struct {
	HTTPPort         int
	RedisAddr        string
	RedisPassword    string
	RedisKey         string
	MinioEndpoint    string
	MinioAccessKey   string
	MinioSecretKey   string
	MinioUseSSL      bool
	MinioStatsBucket string
	MinioStatsPrefix string
	AllowedOrigins   []string
}

// ObjectKey returns the MinIO object key for the current snapshot.
func (c Config) ObjectKey() string {
	return c.MinioStatsPrefix + "latest.json"
}

// Load reads configuration from the environment, applying defaults for
// anything unset or malformed.
func Load() Config {
	return Config{
		HTTPPort:         intEnv("STATS_HTTP_PORT", DefaultHTTPPort),
		RedisAddr:        strEnv("REDIS_ADDR", DefaultRedisAddr),
		RedisPassword:    os.Getenv("REDIS_PASSWORD"),
		RedisKey:         strEnv("REDIS_KEY", DefaultRedisKey),
		MinioEndpoint:    normalizeEndpoint(strEnv("MINIO_ENDPOINT", DefaultMinioEndpoint)),
		MinioAccessKey:   os.Getenv("MINIO_ACCESS_KEY"),
		MinioSecretKey:   os.Getenv("MINIO_SECRET_KEY"),
		MinioUseSSL:      boolEnv("MINIO_USE_SSL", false),
		MinioStatsBucket: strEnv("MINIO_STATS_BUCKET", DefaultMinioStatsBucket),
		MinioStatsPrefix: strEnv("MINIO_STATS_PREFIX", DefaultMinioStatsPrefix),
		AllowedOrigins:   allowedOrigins(),
	}
}

func allowedOrigins() []string {
	v, ok := os.LookupEnv("STATS_ALLOWED_ORIGINS")
	if !ok {
		out := make([]string, len(DefaultAllowedOrigins))
		copy(out, DefaultAllowedOrigins)
		return out
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// normalizeEndpoint strips an optional URL scheme so the value can be
// passed to the MinIO client, which takes host:port plus a TLS flag.
func normalizeEndpoint(ep string) string {
	ep = strings.TrimPrefix(ep, "https://")
	ep = strings.TrimPrefix(ep, "http://")
	return strings.TrimSuffix(ep, "/")
}

func strEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func intEnv(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func boolEnv(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
