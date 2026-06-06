package textbuilder

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

func TestBuildBatchRejectsUnsupportedKind(t *testing.T) {
	_, err := BuildBatch(context.Background(), nil, []db.EmbeddingJob{{
		SourceKey:     "key",
		EmbeddingKind: "unsupported",
	}})

	require.ErrorContains(t, err, "unsupported embedding_kind")
}
