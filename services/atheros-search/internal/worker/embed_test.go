package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
)

func TestIsPermanentEmbedErrorClassifiesHTTPStatus(t *testing.T) {
	require.True(t, isPermanentEmbedError(errors.New("embedding backend returned 400 Bad Request")))
	require.True(t, isPermanentEmbedError(errors.New("embedding backend returned status=400")))
	require.False(t, isPermanentEmbedError(errors.New("embedding backend retry after 4000 milliseconds")))
	require.False(t, isPermanentEmbedError(errors.New("embedding backend returned 429 Too Many Requests")))
	require.False(t, isPermanentEmbedError(errors.New("embedding backend returned 503 Service Unavailable")))
	require.False(t, isPermanentEmbedError(context.DeadlineExceeded))
	require.False(t, isPermanentEmbedError(embed.ErrCircuitOpen))
	require.True(t, isPermanentEmbedError(errors.New("embedding vector dimension mismatch")))
}

func TestCopyCountsIsIndependent(t *testing.T) {
	original := map[string]int{"event": 1}
	got := copyCounts(original)
	original["event"] = 2

	require.Equal(t, map[string]int{"event": 1}, got)
}
