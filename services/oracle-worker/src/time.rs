use chrono::Utc;
use chrono_tz::Tz;

const EASTERN_TIME_ZONE: Tz = chrono_tz::America::New_York;

pub fn now_rfc3339() -> String {
    Utc::now().with_timezone(&EASTERN_TIME_ZONE).to_rfc3339()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::EASTERN_TIME_ZONE;

    #[test]
    fn eastern_timezone_tracks_dst() {
        let summer = Utc
            .with_ymd_and_hms(2026, 7, 1, 12, 30, 0)
            .unwrap()
            .with_timezone(&EASTERN_TIME_ZONE);
        let winter = Utc
            .with_ymd_and_hms(2026, 1, 1, 12, 30, 0)
            .unwrap()
            .with_timezone(&EASTERN_TIME_ZONE);

        assert_eq!(summer.to_rfc3339(), "2026-07-01T08:30:00-04:00");
        assert_eq!(winter.to_rfc3339(), "2026-01-01T07:30:00-05:00");
    }
}
