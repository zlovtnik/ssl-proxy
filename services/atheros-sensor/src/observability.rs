use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use std::time::Duration;

pub fn init_tracer_provider(service_name: &str) -> Option<SdkTracerProvider> {
    global::set_text_map_propagator(TraceContextPropagator::new());

    if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_none()
        && std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_none()
    {
        return None;
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_timeout(Duration::from_secs(5))
        .build()
    {
        Ok(exporter) => exporter,
        Err(error) => {
            eprintln!("failed to initialize OTLP span exporter: {error}");
            return None;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());
    Some(provider)
}
