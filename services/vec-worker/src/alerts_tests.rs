
use super::*;
use chrono::TimeZone;

fn observation(
    cluster_id: i64,
    sensor_id: &str,
    location_id: &str,
    observed_at: DateTime<Utc>,
    latitude: f64,
    longitude: f64,
) -> TravelObservation {
    TravelObservation {
        cluster_id,
        source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
        sensor_id: sensor_id.to_string(),
        location_id: location_id.to_string(),
        observed_at,
        latitude,
        longitude,
    }
}

#[test]
fn termination_filter_matches_raw_and_semantic_tokens() {
    assert!(has_termination_token("AUTH DEAUTH", None));
    assert!(has_termination_token(
        "AUTH ASSOC_REQ",
        Some("DISCOVERY TERMINATION")
    ));
    assert!(!has_termination_token(
        "PROBE_REQ AUTH ASSOC_REQ",
        Some("DISCOVERY ASSOCIATION")
    ));
}

#[test]
fn haversine_distance_is_close_for_one_equator_degree() {
    let meters = haversine_meters(0.0, 0.0, 0.0, 1.0);
    assert!((meters - 111_195.0).abs() < 250.0);
}

#[test]
fn impossible_travel_speed_requires_distinct_sensor_or_location() {
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let t1 = Utc.timestamp_opt(1_700_000_060, 0).unwrap();
    let same_sensor = observation(1, "sensor-a", "", t0, 0.0, 0.0);
    let same_sensor_later = observation(1, "sensor-a", "", t1, 0.0, 1.0);
    assert!(impossible_travel_speed_mps(&same_sensor, &same_sensor_later).is_none());

    let other_sensor = observation(1, "sensor-b", "", t1, 0.0, 1.0);
    let speed = impossible_travel_speed_mps(&same_sensor, &other_sensor).unwrap();
    assert!(speed > 1_800.0);
}
