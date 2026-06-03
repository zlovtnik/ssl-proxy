package embed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQueryCacheExpiresAndInvalidatesByKind(t *testing.T) {
	t.Run("expires", func(t *testing.T) {
		cache := NewQueryCache(2, time.Millisecond)
		cache.Put("query", KindEvent, []float32{1, 2})
		time.Sleep(2 * time.Millisecond)

		_, ok := cache.Get("query", KindEvent)
		require.False(t, ok)
	})

	cache := NewQueryCache(2, time.Hour)
	cache.Put("query", KindEvent, []float32{1, 2})
	got, ok := cache.Get("query", KindEvent)
	require.True(t, ok)
	require.Equal(t, []float32{1, 2}, got)

	cache.InvalidateKind(KindEvent)
	_, ok = cache.Get("query", KindEvent)
	require.False(t, ok)
}

func TestCircuitClientOpensAfterFailures(t *testing.T) {
	client := NewCircuitClient(failingClient{})
	client.FailureMax = 2
	client.OpenBackoff = time.Hour

	_, err := client.Embed(context.Background(), []string{"a"}, KindEvent)
	require.Error(t, err)
	_, err = client.Embed(context.Background(), []string{"a"}, KindEvent)
	require.Error(t, err)
	require.Equal(t, CircuitOpen, client.State())
	_, err = client.Embed(context.Background(), []string{"a"}, KindEvent)
	require.ErrorIs(t, err, ErrCircuitOpen)
}

type failingClient struct{}

func (failingClient) Embed(context.Context, []string, Kind) ([][]float32, error) {
	return nil, errors.New("backend down")
}

func (failingClient) Health(context.Context) error {
	return errors.New("backend down")
}

func TestResponseErrorTextPrefersStructuredError(t *testing.T) {
	got := responseErrorText([]byte(`{"error":{"message":"backend overloaded"}}`))

	require.Equal(t, `{"message":"backend overloaded"}`, got)
}
