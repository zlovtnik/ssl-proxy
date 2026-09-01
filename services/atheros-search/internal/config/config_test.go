package config

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setRequiredPostgresEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ATHSEARCH_POSTGRES_HOST",
		"ATHSEARCH_POSTGRES_PASSWORD",
		"ATHSEARCH_POSTGRES_PASSWORD_FILE",
		"ATHSEARCH_POSTGRES_TLS_CERT_FILE",
		"ATHSEARCH_POSTGRES_TLS_KEY_FILE",
		"ATHSEARCH_POSTGRES_MAX_OPEN_CONNS",
		"ATHSEARCH_POSTGRES_MAX_IDLE_CONNS",
		"ATHSEARCH_DENSE_OVERFETCH_FACTOR",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgresql://search:secret@postgres.example.test:5432/sync?sslmode=verify-full&search_path=atheros_search")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_CA_FILE", "/tls/ca.crt")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME", "postgres.example.test")
	t.Setenv("ATHSEARCH_SCHEMA_MANIFEST_SHA256", hex.EncodeToString(make([]byte, sha256.Size)))
	for _, key := range []string{"ATHSEARCH_API_TOKEN_SHA256", "ATHSEARCH_JWT_ISSUER", "ATHSEARCH_JWT_JWKS_URI", "ATHSEARCH_JWT_AUDIENCE", "ATHSEARCH_JWT_CLIENT_ID"} {
		t.Setenv(key, "")
	}
}

func TestLoadReadsPostgresPasswordFromFile(t *testing.T) {
	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "")
	t.Setenv("ATHSEARCH_POSTGRES_HOST", "postgres.example.test")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_CA_FILE", "")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME", "")
	path := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(path, []byte("file secret\n"), 0o600))
	t.Setenv("ATHSEARCH_POSTGRES_PASSWORD_FILE", path)

	cfg, err := Load()
	require.NoError(t, err)
	parsed, err := url.Parse(cfg.PostgresDSN)
	require.NoError(t, err)
	password, present := parsed.User.Password()
	require.True(t, present)
	require.Equal(t, "file secret", password)

	t.Setenv("ATHSEARCH_POSTGRES_PASSWORD", "ambiguous")
	_, err = Load()
	require.ErrorContains(t, err, "cannot both be configured")
}

func TestLoadValidatesJWTConfiguration(t *testing.T) {
	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_JWT_ISSUER", "https://gateway.example.test/realms/middleware")
	_, err := Load()
	require.ErrorContains(t, err, "must be configured together")

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_JWT_ISSUER", "https://gateway.example.test/realms/middleware")
	t.Setenv("ATHSEARCH_JWT_JWKS_URI", "https://keycloak.example.test/realms/middleware/protocol/openid-connect/certs")
	t.Setenv("ATHSEARCH_JWT_AUDIENCE", "atheros-search-ui")
	t.Setenv("ATHSEARCH_JWT_CLIENT_ID", "atheros-search-ui")
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, "atheros-search-ui", cfg.JWTAudience)

	sum := sha256.Sum256([]byte("token"))
	t.Setenv("ATHSEARCH_API_TOKEN_SHA256", hex.EncodeToString(sum[:]))
	_, err = Load()
	require.ErrorContains(t, err, "cannot be combined")
}

func TestLoadRequiresPostgresConnectionURL(t *testing.T) {
	setRequiredPostgresEnv(t)

	cfg, err := Load()
	require.NoError(t, err)
	require.Contains(t, cfg.PostgresDSN, "postgres.example.test:5432/sync")
	require.Equal(t, "/tls/ca.crt", cfg.PostgresTLSCAFile)
	require.Equal(t, "postgres.example.test", cfg.PostgresTLSServerName)
	require.Equal(t, 32, cfg.PostgresMaxOpenConns)
	require.Equal(t, 8, cfg.PostgresMaxIdleConns)
	require.Equal(t, 5*time.Minute, cfg.PostgresConnMaxLifetime)
	require.Equal(t, time.Minute, cfg.PostgresConnMaxIdleTime)
	require.Equal(t, 8, cfg.DenseOverfetchFactor)
}

func TestLoadBuildsPasswordBasedPostgresConfigurationWithoutTLS(t *testing.T) {
	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "")
	t.Setenv("ATHSEARCH_POSTGRES_HOST", "postgres.example.test")
	t.Setenv("ATHSEARCH_POSTGRES_PORT", "5432")
	t.Setenv("ATHSEARCH_POSTGRES_DATABASE", "sync")
	t.Setenv("ATHSEARCH_POSTGRES_USER", "atheros_search_runtime")
	t.Setenv("ATHSEARCH_POSTGRES_PASSWORD", "p@ss:/ word")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_CA_FILE", "")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME", "")

	cfg, err := Load()
	require.NoError(t, err)
	parsed, err := url.Parse(cfg.PostgresDSN)
	require.NoError(t, err)
	require.Equal(t, "postgres.example.test", parsed.Hostname())
	require.Equal(t, "5432", parsed.Port())
	require.Equal(t, "/sync", parsed.Path)
	require.Equal(t, "atheros_search_runtime", parsed.User.Username())
	password, present := parsed.User.Password()
	require.True(t, present)
	require.Equal(t, "p@ss:/ word", password)
	require.Equal(t, "disable", parsed.Query().Get("sslmode"))

	t.Setenv("ATHSEARCH_POSTGRES_TLS_CA_FILE", "/tls/ca.crt")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME", "postgres.example.test")
	cfg, err = Load()
	require.NoError(t, err)
	parsed, err = url.Parse(cfg.PostgresDSN)
	require.NoError(t, err)
	require.Equal(t, "verify-full", parsed.Query().Get("sslmode"))
}

func TestLoadRejectsRemovedDatabaseURLsAndGenericFallbacks(t *testing.T) {
	setRequiredPostgresEnv(t)
	for _, scheme := range []string{"maria" + "db", "oracle"} {
		t.Run(scheme, func(t *testing.T) {
			t.Setenv("ATHSEARCH_POSTGRES_DSN", scheme+"://search:secret@db.example.test:5432/sync")
			_, err := Load()
			require.ErrorContains(t, err, "PostgreSQL connection URL")
		})
	}

	t.Setenv("ATHSEARCH_POSTGRES_DSN", "")
	t.Setenv("DATABASE"+"_URL", "postgresql://search:secret@postgres.example.test:5432/sync")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_POSTGRES_HOST is required")
}

func TestLoadAllowsDisabledTLSAndValidatesPartialTLSAndManifest(t *testing.T) {
	setRequiredPostgresEnv(t)

	t.Setenv("ATHSEARCH_POSTGRES_TLS_CA_FILE", "")
	t.Setenv("ATHSEARCH_POSTGRES_TLS_SERVER_NAME", "")
	_, err := Load()
	require.NoError(t, err)

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgresql://search:secret@postgres.example.test:5432/sync?sslmode=require")
	_, err = Load()
	require.ErrorContains(t, err, "sslmode=verify-full")

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_TLS_CERT_FILE", "/tls/client.crt")
	_, err = Load()
	require.ErrorContains(t, err, "configured together")

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_SCHEMA_MANIFEST_SHA256", "not-a-checksum")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_SCHEMA_MANIFEST_SHA256")
}

func TestLoadValidatesDimensionsAndAuthDigest(t *testing.T) {
	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_EMBEDDING_DIMENSIONS", "384")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_EMBEDDING_DIMENSIONS")

	t.Setenv("ATHSEARCH_EMBEDDING_DIMENSIONS", "768")
	t.Setenv("ATHSEARCH_API_TOKEN_SHA256", "not-hex")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_API_TOKEN_SHA256")

	sum := sha256.Sum256([]byte("token"))
	t.Setenv("ATHSEARCH_API_TOKEN_SHA256", hex.EncodeToString(sum[:]))
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, DefaultEmbeddingDimensions, cfg.EmbeddingDimensions)
}

func TestLoadValidatesPoolAndOverfetchBounds(t *testing.T) {
	setRequiredPostgresEnv(t)

	t.Setenv("ATHSEARCH_POSTGRES_MAX_OPEN_CONNS", "0")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_POSTGRES_MAX_OPEN_CONNS")

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_MAX_OPEN_CONNS", "4")
	t.Setenv("ATHSEARCH_POSTGRES_MAX_IDLE_CONNS", "5")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_POSTGRES_MAX_IDLE_CONNS")

	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_DENSE_OVERFETCH_FACTOR", "0")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_DENSE_OVERFETCH_FACTOR")
}

func TestLoadRequiresEmbeddingBackendWhenWorkersAreEnabled(t *testing.T) {
	setRequiredPostgresEnv(t)
	t.Setenv("ATHSEARCH_WORKER_ENABLED", "true")
	t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "")
	t.Setenv("VECTOR_EMBEDDING_URL", "")

	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_EMBEDDING_BACKEND is required")

	t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "https://embedding.example.test/v1/embeddings")
	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.WorkerEnabled)
}

func TestClampTopK(t *testing.T) {
	require.Equal(t, 10, ClampTopK(0))
	require.Equal(t, 42, ClampTopK(42))
	require.Equal(t, 100, ClampTopK(101))
}

func TestDBKindMapsAPIWordsToSchemaValues(t *testing.T) {
	got, ok := DBKind("behaviour")
	require.True(t, ok)
	require.Equal(t, "behaviour_window", got)
	got, ok = DBKind("sequence")
	require.True(t, ok)
	require.Equal(t, "frame_sequence", got)
}
