//! Audit-window-gated tracing layer for compliance logging.
//!
//! This tracing_subscriber Layer mirrors log events to stdout or stderr only during active
//! audit windows. It is not a general-purpose logger—it exists solely to capture diagnostic
//! traces when the audit schedule gate is open, enabling time-bounded compliance monitoring.
//!
//! To avoid holding a read lock on [`SharedAuditWindow`] per `on_event()` call (a hot
//! contention point under high frame rates), the active/inactive state is updated by a
//! dedicated background task every 5 seconds and stored as an [`AtomicBool`] snapshot.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde_json::json;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use crate::config::AuditLayerStream;

/// Holds the audit window active snapshot and output stream destination. The active field
/// is updated by a background task every 5 seconds, avoiding a per-event read lock on the
/// shared audit window.
pub struct AuditLayer {
    is_active: Arc<AtomicBool>,
    stream: AuditLayerStream,
}

impl AuditLayer {
    /// Constructs a new AuditLayer with the given atomic active flag and stream destination.
    pub fn new(is_active: Arc<AtomicBool>, stream: AuditLayerStream) -> Self {
        Self { is_active, stream }
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
        if !self.is_active.load(Ordering::Acquire) {
            return;
        }
        let now = chrono::Utc::now();
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

/// Private tracing field visitor that collects key-value pairs into a JSON map.
/// Used only by on_event to serialize structured log fields.
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