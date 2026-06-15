use chrono::Utc;
use chrono_tz::Tz;

const EASTERN_TIME_ZONE: Tz = chrono_tz::America::New_York;

pub(crate) fn now_rfc3339() -> String {
    Utc::now().with_timezone(&EASTERN_TIME_ZONE).to_rfc3339()
}

pub(crate) fn file_token_now() -> String {
    Utc::now()
        .with_timezone(&EASTERN_TIME_ZONE)
        .format("%Y%m%dT%H%M%S%f%z")
        .to_string()
}
