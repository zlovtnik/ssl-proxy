use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
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
                        "invalid audit window timezone; defaulting to UTC"
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
