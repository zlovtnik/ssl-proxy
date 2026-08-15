use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use axum::{body::Body, http::Request};
use tower::ServiceExt;

use super::{
    admin_api_key_matches, build_observability_router, build_state, constant_time_eq,
    AdminAuthRateLimiter, ADMIN_AUTH_FAILURE_WINDOW, ADMIN_AUTH_MAX_FAILURES,
    ADMIN_AUTH_MAX_TRACKED_IPS,
};

#[test]
fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
    assert!(!constant_time_eq("prefix", "prefix-suffix"));
}

#[test]
fn constant_time_eq_handles_long_inputs() {
    let a = "a".repeat(300);
    let b = "a".repeat(300);

    assert!(constant_time_eq(&a, &b));
}

#[test]
fn admin_api_key_matches_rejects_empty_keys() {
    assert!(!admin_api_key_matches("", ""));
    assert!(!admin_api_key_matches("test-key", ""));
    assert!(admin_api_key_matches("test-key", "test-key"));
}

#[test]
fn admin_auth_rate_limiter_evicts_expired_failures() {
    let limiter = AdminAuthRateLimiter::default();
    let now = Instant::now();
    let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

    assert_eq!(limiter.record_failure(first_ip, now), 1);
    assert_eq!(
        limiter.record_failure(
            second_ip,
            now + ADMIN_AUTH_FAILURE_WINDOW + Duration::from_millis(1),
        ),
        1
    );

    assert!(limiter.failures_by_ip.get(&first_ip).is_none());
    assert!(limiter.failures_by_ip.get(&second_ip).is_some());
}

#[test]
fn admin_auth_rate_limiter_fails_closed_when_saturated() {
    let limiter = AdminAuthRateLimiter::default();
    let now = Instant::now();

    for idx in 0..ADMIN_AUTH_MAX_TRACKED_IPS {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            ((idx >> 16) & 0xff) as u8,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        assert_eq!(limiter.record_failure(ip, now), 1);
    }

    let saturated_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(
        limiter.record_failure(saturated_ip, now),
        ADMIN_AUTH_MAX_FAILURES
    );
    assert!(limiter.failures_by_ip.get(&saturated_ip).is_none());
}

#[tokio::test]
async fn observability_listener_exposes_no_admin_routes() {
    let state = build_state(&ssl_proxy::config::Config::default()).unwrap();
    let router = build_observability_router(state);

    for path in ["/hosts", "/stats/summary", "/devices", "/dashboard"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}
