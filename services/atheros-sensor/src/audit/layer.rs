use chrono::Utc;
use serde_json::json;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use super::SharedAuditWindow;
use crate::config::AuditLayerStream;

pub struct AuditLayer {
    window: SharedAuditWindow,
    stream: AuditLayerStream,
}

impl AuditLayer {
    pub fn new(window: SharedAuditWindow, stream: AuditLayerStream) -> Self {
        Self { window, stream }
    }
}

impl<S> Layer<S> for AuditLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if let AuditLayerStream::Off = self.stream {
            return;
        }
        let now = Utc::now();
        let active = self
            .window
            .read()
            .map(|window| window.is_active_at(now))
            .unwrap_or(true);
        if !active {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let line = json!({
            "type": "audit_trace",
            "time": ssl_proxy::time::rfc3339_from_utc(now),
            "target": event.metadata().target(),
            "level": event.metadata().level().as_str(),
            "fields": visitor.fields,
        })
        .to_string();
        match self.stream {
            AuditLayerStream::Off => {}
            AuditLayerStream::Stdout => println!("{line}"),
            AuditLayerStream::Stderr => eprintln!("{line}"),
        }
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
}
