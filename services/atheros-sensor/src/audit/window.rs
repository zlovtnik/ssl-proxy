//! Schedule gate for audit window filtering.
//!
//! Controls when audit activity is enabled based on timezone, weekday, and time range.
//! When unconfigured (all fields None), the gate passes everything through. When configured,
//! it filters by localized time, allowing compliance monitoring only during specified windows.
//!
//! When all four fields are `None`, `is_active_at` unconditionally returns `true`; this is
//! the default out-of-the-box behavior and means the sensor captures continuously until an
//! explicit window is pushed via Redpanda or set via environment variables.

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
use ssl_proxy::time::EASTERN_TIME_ZONE;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct AuditWindow {
    timezone: Option<Tz>,
    days: Option<HashSet<Weekday>>,
    start: Option<NaiveTime>,
    end: Option<NaiveTime>,
}

pub type SharedAuditWindow = Arc<RwLock<AuditWindow>>;

impl AuditWindow {
    pub fn from_parts(
        timezone: Option<String>,
        days: Option<String>,
        start: Option<NaiveTime>,
        end: Option<NaiveTime>,
    ) -> Self {
        let timezone = timezone.as_ref().and_then(|value| {
            value.parse::<Tz>().map_or_else(
                |error| {
                    warn!(
                        timezone = %value,
                        %error,
                        "invalid audit window timezone; defaulting to America/New_York"
                    );
                    None
                },
                Some,
            )
        });

        Self {
            timezone,
            days: days.map(|value| parse_days(&value)),
            start,
            end,
        }
    }

    /// Returns true if the instant falls within the configured window.
    /// When start > end, the window wraps overnight (e.g. 22:00–06:00), and the check
    /// passes if current time is >= start OR <= end.
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
            None => instant.with_timezone(&EASTERN_TIME_ZONE),
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
            (Some(start), None) => localized.time() >= start,
            (None, Some(end)) => localized.time() <= end,
            (None, None) => true,
        }
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
