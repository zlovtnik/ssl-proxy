package config

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadValidatesDimensionsAndAuthDigest(t *testing.T) {
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
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
