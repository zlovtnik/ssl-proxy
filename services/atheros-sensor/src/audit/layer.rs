use chrono::Utc;
use serde_json::json;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use super::SharedAuditWindow;

pub struct AuditLayer {
    window: SharedAuditWindow,
}

impl AuditLayer {
    pub fn new(window: SharedAuditWindow) -> Self {
        Self { window }
    }
}

impl<S> Layer<S> for AuditLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
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
        eprintln!(
            "{}",
            json!({
                "type": "audit_trace",
                "time": now.to_rfc3339(),
                "target": event.metadata().target(),
                "level": event.metadata().level().as_str(),
                "fields": visitor.fields,
            })
        );
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
