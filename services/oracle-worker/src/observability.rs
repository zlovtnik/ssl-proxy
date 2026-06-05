use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
    Context,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub(crate) fn init_tracing(service_name: &str) -> Option<SdkTracerProvider> {
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
        .with_simple_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());

    let otel_layer = {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer(service_name.to_string()))
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("oracle_worker=info,oracle-worker=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(otel_layer)
        .init();

    Some(provider)
}

pub(crate) fn shutdown_tracer_provider(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider {
        let _ = provider.shutdown();
    }
}

pub(crate) fn current_trace_headers() -> Vec<(String, String)> {
    let mut injector = HeaderInjector {
        headers: Vec::new(),
    };
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&Context::current(), &mut injector);
    });
    injector.headers
}

pub(crate) fn extract_trace_context(headers: &[(String, String)]) -> Context {
    let extractor = HeaderExtractor { headers };
    global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

struct HeaderInjector {
    headers: Vec<(String, String)>,
}

impl Injector for HeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.headers.push((key.to_string(), value));
    }
}

struct HeaderExtractor<'a> {
    headers: &'a [(String, String)],
}

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
    }
}
