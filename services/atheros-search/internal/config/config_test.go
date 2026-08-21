package config

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setRequiredTiDBEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ATHSEARCH_TIDB_HOST",
		"ATHSEARCH_TIDB_PASSWORD",
		"ATHSEARCH_TIDB_TLS_CERT_FILE",
		"ATHSEARCH_TIDB_TLS_KEY_FILE",
		"ATHSEARCH_TIDB_MAX_OPEN_CONNS",
		"ATHSEARCH_TIDB_MAX_IDLE_CONNS",
		"ATHSEARCH_DENSE_OVERFETCH_FACTOR",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ATHSEARCH_TIDB_DSN", "search:secret@tcp(tidb.example.test:4000)/atheros_search")
	t.Setenv("ATHSEARCH_TIDB_TLS_CA_FILE", "/tls/ca.crt")
	t.Setenv("ATHSEARCH_TIDB_TLS_SERVER_NAME", "tidb.example.test")
	t.Setenv("ATHSEARCH_SCHEMA_MANIFEST_SHA256", hex.EncodeToString(make([]byte, sha256.Size)))
}

func TestLoadRequiresNativeTiDBConfiguration(t *testing.T) {
	setRequiredTiDBEnv(t)

	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, "search:secret@tcp(tidb.example.test:4000)/atheros_search", cfg.TiDBDSN)
	require.Equal(t, "/tls/ca.crt", cfg.TiDBTLSCAFile)
	require.Equal(t, "tidb.example.test", cfg.TiDBTLSServerName)
	require.Equal(t, 32, cfg.TiDBMaxOpenConns)
	require.Equal(t, 8, cfg.TiDBMaxIdleConns)
	require.Equal(t, 5*time.Minute, cfg.TiDBConnMaxLifetime)
	require.Equal(t, time.Minute, cfg.TiDBConnMaxIdleTime)
	require.Equal(t, 8, cfg.DenseOverfetchFactor)
}

func TestLoadBuildsPasswordBasedTiDBConfigurationWithoutTLS(t *testing.T) {
	setRequiredTiDBEnv(t)
	t.Setenv("ATHSEARCH_TIDB_DSN", "")
	t.Setenv("ATHSEARCH_TIDB_HOST", "tidb.example.test")
	t.Setenv("ATHSEARCH_TIDB_PORT", "4000")
	t.Setenv("ATHSEARCH_TIDB_DATABASE", "atheros_search")
	t.Setenv("ATHSEARCH_TIDB_USER", "atheros_search_runtime")
	t.Setenv("ATHSEARCH_TIDB_PASSWORD", "secret")
	t.Setenv("ATHSEARCH_TIDB_TLS_CA_FILE", "")
	t.Setenv("ATHSEARCH_TIDB_TLS_SERVER_NAME", "")

	cfg, err := Load()
	require.NoError(t, err)
	require.Contains(t, cfg.TiDBDSN, "atheros_search_runtime:secret@tcp(tidb.example.test:4000)/atheros_search")
	require.Empty(t, cfg.TiDBTLSCAFile)
	require.Empty(t, cfg.TiDBTLSServerName)
}

func TestLoadRejectsURLStyleDSNsAndGenericFallbacks(t *testing.T) {
	setRequiredTiDBEnv(t)
	for _, scheme := range []string{
		"post" + "gres",
		"post" + "gresql",
		"my" + "sql",
	} {
		t.Run(scheme, func(t *testing.T) {
			t.Setenv("ATHSEARCH_TIDB_DSN", scheme+"://search:secret@db.example.test:4000/atheros_search")
			_, err := Load()
			require.ErrorContains(t, err, "native MySQL DSN")
		})
	}

	t.Setenv("ATHSEARCH_TIDB_DSN", "")
	t.Setenv("DATABASE"+"_URL", "search:secret@tcp(tidb.example.test:4000)/atheros_search")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_TIDB_HOST is required")
}

func TestLoadAllowsDisabledTLSAndValidatesPartialTLSAndManifest(t *testing.T) {
	setRequiredTiDBEnv(t)

	t.Setenv("ATHSEARCH_TIDB_TLS_CA_FILE", "")
	t.Setenv("ATHSEARCH_TIDB_TLS_SERVER_NAME", "")
	_, err := Load()
	require.NoError(t, err)

	setRequiredTiDBEnv(t)
	t.Setenv("ATHSEARCH_TIDB_TLS_CERT_FILE", "/tls/client.crt")
	_, err = Load()
	require.ErrorContains(t, err, "configured together")

	setRequiredTiDBEnv(t)
	t.Setenv("ATHSEARCH_SCHEMA_MANIFEST_SHA256", "not-a-checksum")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_SCHEMA_MANIFEST_SHA256")
}

func TestLoadValidatesDimensionsAndAuthDigest(t *testing.T) {
	setRequiredTiDBEnv(t)
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
	setRequiredTiDBEnv(t)

	t.Setenv("ATHSEARCH_TIDB_MAX_OPEN_CONNS", "0")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_TIDB_MAX_OPEN_CONNS")

	setRequiredTiDBEnv(t)
	t.Setenv("ATHSEARCH_TIDB_MAX_OPEN_CONNS", "4")
	t.Setenv("ATHSEARCH_TIDB_MAX_IDLE_CONNS", "5")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_TIDB_MAX_IDLE_CONNS")

	setRequiredTiDBEnv(t)
	t.Setenv("ATHSEARCH_DENSE_OVERFETCH_FACTOR", "0")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_DENSE_OVERFETCH_FACTOR")
}

func TestLoadRequiresEmbeddingBackendWhenWorkersAreEnabled(t *testing.T) {
	setRequiredTiDBEnv(t)
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
