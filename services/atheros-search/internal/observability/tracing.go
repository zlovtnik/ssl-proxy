package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// InitTracing configures the process-wide trace provider. The OTLP exporter
// follows the standard OTEL_EXPORTER_OTLP_* environment variables.
func InitTracing(ctx context.Context, serviceName string) (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}
	provider := NewTracerProvider(serviceName, exporter)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return provider, nil
}

// NewTracerProvider is separated from exporter construction so tests can use
// an in-memory exporter without opening a network connection.
func NewTracerProvider(serviceName string, exporter sdktrace.SpanExporter) *sdktrace.TracerProvider {
	serviceResource := resource.NewSchemaless(attribute.String("service.name", serviceName))
	merged, err := resource.Merge(resource.Default(), serviceResource)
	if err != nil {
		merged = serviceResource
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(merged),
	)
}
