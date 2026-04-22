use std::collections::HashSet;

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
use serde_json::json;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

#[derive(Clone, Debug)]
pub struct AuditWindow {
    timezone: Option<Tz>,
    days: Option<HashSet<Weekday>>,
    start: Option<NaiveTime>,
    end: Option<NaiveTime>,
}

impl AuditWindow {
    pub fn from_parts(
        timezone: Option<String>,
        days: Option<String>,
        start: Option<NaiveTime>,
        end: Option<NaiveTime>,
    ) -> Self {
        Self {
            timezone: timezone.and_then(|value| value.parse::<Tz>().ok()),
            days: days.map(|value| parse_days(&value)),
            start,
            end,
        }
    }

    pub fn is_active_at(&self, instant: DateTime<Utc>) -> bool {
        if self.timezone.is_none()
            && self.days.is_none()
            && self.start.is_none()
            && self.end.is_none()
        {
            return true;
        }

        let localized = match self.timezone {
            Some(timezone) => instant.with_timezone(&timezone),
            None => instant.with_timezone(&chrono_tz::UTC),
        };
        if let Some(days) = &self.days {
            if !days.contains(&localized.weekday()) {
                return false;
            }
        }

        match (self.start, self.end) {
            (Some(start), Some(end)) if start <= end => {
                let current = localized.time();
                current >= start && current <= end
            }
            (Some(start), Some(end)) => {
                let current = localized.time();
                current >= start || current <= end
            }
            _ => true,
        }
    }
}

pub struct AuditLayer {
    window: AuditWindow,
}

impl AuditLayer {
    pub fn new(window: AuditWindow) -> Self {
        Self { window }
    }
}

impl<S> Layer<S> for AuditLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let now = Utc::now();
        if !self.window.is_active_at(now) {
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

fn parse_days(value: &str) -> HashSet<Weekday> {
    value
        .split(',')
        .filter_map(|token| match token.trim().to_ascii_lowercase().as_str() {
            "mon" | "monday" => Some(Weekday::Mon),
            "tue" | "tuesday" => Some(Weekday::Tue),
            "wed" | "wednesday" => Some(Weekday::Wed),
            "thu" | "thursday" => Some(Weekday::Thu),
            "fri" | "friday" => Some(Weekday::Fri),
            "sat" | "saturday" => Some(Weekday::Sat),
            "sun" | "sunday" => Some(Weekday::Sun),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::AuditWindow;

    #[test]
    fn audit_window_defaults_to_always_on() {
        let window = AuditWindow::from_parts(None, None, None, None);
        assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap()));
    }

    #[test]
    fn audit_window_applies_days_and_hours() {
        let window = AuditWindow::from_parts(
            Some("America/New_York".to_string()),
            Some("mon,fri".to_string()),
            Some(chrono::NaiveTime::from_hms_opt(9, 0, 0).unwrap()),
            Some(chrono::NaiveTime::from_hms_opt(17, 0, 0).unwrap()),
        );

        assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 21, 16, 0, 0).unwrap()));
        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 1, 0, 0).unwrap()));
    }
}
