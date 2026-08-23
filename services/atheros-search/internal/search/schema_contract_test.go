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
		"sql/postgres/atheros_search/01_tables/004_projection_state.sql",
		"sql/postgres/atheros_search/01_tables/005_graph_inventory_identity.sql",
		"sql/postgres/atheros_search/01_tables/006_query_feedback.sql",
	}
	combined := ""
	for _, relative := range files {
		body, err := os.ReadFile(filepath.Join(root, relative))
		require.NoError(t, err, relative)
		combined += string(body)
	}
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS atheros_search.schema_manifest",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_documents",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_document_tokens",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_event",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_device",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_behaviour",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_vectors_sequence",
		"CREATE TABLE IF NOT EXISTS atheros_search.threat_signals",
		"CREATE TABLE IF NOT EXISTS atheros_search.sequence_transitions",
		"CREATE TABLE IF NOT EXISTS atheros_search.graph_nodes",
		"CREATE TABLE IF NOT EXISTS atheros_search.graph_edges",
		"CREATE TABLE IF NOT EXISTS atheros_search.inventory_devices",
		"CREATE TABLE IF NOT EXISTS atheros_search.merge_candidates",
		"CREATE TABLE IF NOT EXISTS atheros_search.merge_decisions",
		"decision IN ('merge', 'not_match', 'needs_more_data', 'undo_merge')",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_queries",
		"CREATE TABLE IF NOT EXISTS atheros_search.search_query_results",
		"query_vector      VECTOR(768)",
	} {
		require.Contains(t, combined, required)
	}
}
