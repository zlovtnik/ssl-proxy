use std::time::SystemTime;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;

pub const EASTERN_TIME_ZONE_NAME: &str = "America/New_York";
pub const EASTERN_TIME_ZONE: Tz = chrono_tz::America::New_York;

pub fn now_eastern() -> DateTime<Tz> {
    Utc::now().with_timezone(&EASTERN_TIME_ZONE)
}

pub fn now_rfc3339() -> String {
    now_eastern().to_rfc3339()
}

pub fn rfc3339_from_utc(value: DateTime<Utc>) -> String {
    value.with_timezone(&EASTERN_TIME_ZONE).to_rfc3339()
}

pub fn rfc3339_from_system_time(value: SystemTime) -> String {
    let datetime: DateTime<Utc> = value.into();
    rfc3339_from_utc(datetime)
}

pub fn file_token_now() -> String {
    now_eastern().format("%Y%m%dT%H%M%S%f%z").to_string()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::rfc3339_from_utc;

    #[test]
    fn eastern_rfc3339_uses_daylight_offset() {
        let value = Utc.with_ymd_and_hms(2026, 7, 1, 12, 30, 0).unwrap();

        assert_eq!(rfc3339_from_utc(value), "2026-07-01T08:30:00-04:00");
    }

    #[test]
    fn eastern_rfc3339_uses_standard_offset() {
        let value = Utc.with_ymd_and_hms(2026, 1, 1, 12, 30, 0).unwrap();

        assert_eq!(rfc3339_from_utc(value), "2026-01-01T07:30:00-05:00");
    }
}
