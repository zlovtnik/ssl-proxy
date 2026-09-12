package search

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalPostgresSchemaMatchesQueryFacade(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../../.."))
	files := []string{
		"sql/postgres/atheros_search/01_tables/001_schema_manifest.sql",
		"sql/postgres/atheros_search/01_tables/002_search_documents.sql",
		"sql/postgres/atheros_search/01_tables/003_search_vectors.sql",
		"sql/postgres/atheros_search/01_tables/006_query_feedback.sql",
		"sql/postgres/atheros_search/01_tables/009_embedding_recovery_contract.sql",
	}
	combined := ""
	for _, relative := range files {
		body, err := os.ReadFile(filepath.Join(root, relative))
		require.NoError(t, err, relative)
		combined += string(body)
	}
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS atheros_search.schema_readiness",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_documents",
		"CREATE TABLE IF NOT EXISTS atheros_search.embedding_jobs",
		"CREATE TABLE IF NOT EXISTS atheros_search.devices",
		"CREATE TABLE IF NOT EXISTS atheros_search.embeddings",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_queries",
		"CREATE TABLE IF NOT EXISTS atheros_search.worker_heartbeat",
		"embedding       VECTOR(768) NOT NULL",
		"embedding_kind IN ('event', 'device', 'behaviour', 'sequence')",
		"search_vectors_behaviour",
		"search_vectors_sequence",
		"public.vector",
	} {
		require.Contains(t, combined, required)
	}
}
