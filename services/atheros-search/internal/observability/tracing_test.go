package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracerProviderExportsSpanWithServiceName(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := NewTracerProvider("atheros-search", exporter)
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
	})

	_, span := provider.Tracer("test").Start(context.Background(), "search")
	span.End()
	require.NoError(t, provider.ForceFlush(context.Background()))

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	value, found := spans[0].Resource().Set().Value("service.name")
	require.True(t, found)
	require.Equal(t, "atheros-search", value.AsString())
}
