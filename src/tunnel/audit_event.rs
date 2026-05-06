//! Shared tunnel audit event context and emitters.

use std::time::Duration;

use serde_json::json;

use crate::{
    events::{self, EmitPayload},
    identity::ResolvedIdentity,
    obfuscation,
    state::SharedState,
};

use super::tls::TlsInfo;

#[derive(Clone, Debug)]
pub(crate) struct TunnelAuditContext {
    pub(crate) correlation_id: String,
    pub(crate) kind: &'static str,
    pub(crate) category: &'static str,
    pub(crate) reason: Option<&'static str>,
    pub(crate) obfuscation_profile: Option<String>,
    pub(crate) resolved_ips: Vec<String>,
    pub(crate) selected_ip: Option<String>,
    pub(crate) tls: TlsInfo,
    pub(crate) bypass_reason: Option<&'static str>,
}

impl TunnelAuditContext {
    pub(crate) fn new(
        kind: &'static str,
        category: &'static str,
        reason: Option<&'static str>,
        profile: obfuscation::Profile,
    ) -> Self {
        Self {
            correlation_id: uuid::Uuid::new_v4().to_string(),
            kind,
            category,
            reason,
            obfuscation_profile: if matches!(profile, obfuscation::Profile::None) {
                None
            } else {
                Some(profile.as_str().to_string())
            },
            resolved_ips: Vec::new(),
            selected_ip: None,
            tls: TlsInfo::default(),
            bypass_reason: None,
        }
    }

    pub(crate) fn bypass(kind: &'static str, category: &'static str, reason: &'static str) -> Self {
        let mut context = Self::new(kind, category, Some(reason), obfuscation::Profile::None);
        context.obfuscation_profile = Some("none".to_string());
        context.bypass_reason = Some(reason);
        context
    }

    pub(crate) fn with_resolution(
        mut self,
        resolved_ips: Vec<String>,
        selected_ip: String,
    ) -> Self {
        self.resolved_ips = resolved_ips;
        self.selected_ip = Some(selected_ip);
        self
    }

    pub(crate) fn with_tls(mut self, tls: TlsInfo) -> Self {
        self.tls = tls;
        self
    }

    fn event_extra(
        &self,
        event_sequence: i64,
        bytes_up: u64,
        bytes_down: u64,
        duration: Option<Duration>,
        payload_preview: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut extra = json!({
            "correlation_id": self.correlation_id.clone(),
            "event_sequence": event_sequence,
            "kind": self.kind,
            "category": self.category,
            "reason": self.reason,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
            "duration_ms": duration.map(|value| value.as_millis() as u64),
            "obfuscation_profile": self.obfuscation_profile.clone(),
            "resolved_ips": self.resolved_ips.clone(),
            "selected_ip": self.selected_ip.clone(),
            "tls_ver": self.tls.tls_ver.clone(),
            "alpn": self.tls.alpn.clone(),
            "cipher_suites_count": self.tls.cipher_suites_count,
            "ja3_lite": self.tls.ja3_lite.clone(),
        });

        if let serde_json::Value::Object(ref mut map) = extra {
            if let Some(reason) = self.bypass_reason {
                map.insert("bypass_reason".to_string(), json!(reason));
            }
            if let Some(payload_preview) = payload_preview {
                map.insert("payload_preview".to_string(), payload_preview);
            }
        }

        extra
    }

    pub(crate) fn emit_open(&self, state: &SharedState, host: &str, identity: &ResolvedIdentity) {
        events::emit(
            state,
            "tunnel_open",
            host,
            EmitPayload {
                peer_ip: identity.peer_ip.clone(),
                wg_pubkey: identity.wg_pubkey.clone(),
                device_id: identity.device_id.clone(),
                identity_source: identity.identity_source.clone(),
                peer_hostname: identity.peer_hostname.clone(),
                client_ua: identity.client_ua.clone(),
                bytes_up: 0,
                bytes_down: 0,
                status_code: None,
                blocked: false,
                obfuscation_profile: self.obfuscation_profile.clone(),
                extra: self.event_extra(1, 0, 0, None, None),
            },
        );
    }

    pub(crate) fn emit_close(
        &self,
        state: &SharedState,
        host: &str,
        identity: &ResolvedIdentity,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
        payload_preview: Option<serde_json::Value>,
    ) {
        events::emit(
            state,
            "tunnel_close",
            host,
            EmitPayload {
                peer_ip: identity.peer_ip.clone(),
                wg_pubkey: identity.wg_pubkey.clone(),
                device_id: identity.device_id.clone(),
                identity_source: identity.identity_source.clone(),
                peer_hostname: identity.peer_hostname.clone(),
                client_ua: identity.client_ua.clone(),
                bytes_up,
                bytes_down,
                status_code: None,
                blocked: false,
                obfuscation_profile: self.obfuscation_profile.clone(),
                extra: self.event_extra(2, bytes_up, bytes_down, Some(duration), payload_preview),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::TokioAsyncResolver;
    use hyper_util::client::legacy::connect::HttpConnector;
    use serde_json::Value;
    use tokio::sync::broadcast;

    use super::*;
    use crate::{config::Config, state::AppState};

    fn identity() -> ResolvedIdentity {
        ResolvedIdentity {
            peer_ip: Some("10.0.0.2".to_string()),
            wg_pubkey: Some("pubkey".to_string()),
            device_id: Some("device-1".to_string()),
            identity_source: Some("registered".to_string()),
            peer_hostname: Some("phone.local".to_string()),
            client_ua: Some("UA".to_string()),
        }
    }

    fn state() -> SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            Config::default(),
        )
    }

    #[tokio::test]
    async fn open_and_close_share_correlation_and_context() {
        let state = state();
        let mut rx = state.events_tx.subscribe();
        let context = TunnelAuditContext::new(
            "transparent",
            "analytics",
            Some("allowed_sni"),
            obfuscation::Profile::None,
        )
        .with_resolution(vec!["192.0.2.10".to_string()], "192.0.2.10".to_string())
        .with_tls(TlsInfo {
            sni: Some("example.com".to_string()),
            alpn: Some("h2".to_string()),
            tls_ver: Some("TLS1.3".to_string()),
            cipher_suites_count: Some(4),
            ja3_lite: Some("ja3-lite".to_string()),
        });

        context.emit_open(&state, "example.com", &identity());
        context.emit_close(
            &state,
            "example.com",
            &identity(),
            12,
            34,
            Duration::from_millis(56),
            None,
        );

        let open: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        let close: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();

        assert_eq!(open["type"], "tunnel_open");
        assert_eq!(close["type"], "tunnel_close");
        assert_eq!(open["correlation_id"], close["correlation_id"]);
        assert_eq!(open["event_sequence"], 1);
        assert_eq!(close["event_sequence"], 2);
        assert_eq!(close["duration_ms"], 56);
        assert_eq!(close["tls_ver"], "TLS1.3");
        assert_eq!(close["alpn"], "h2");
        assert_eq!(close["cipher_suites_count"], 4);
        assert_eq!(close["ja3_lite"], "ja3-lite");
        assert_eq!(close["selected_ip"], "192.0.2.10");
        assert_eq!(close["resolved_ips"][0], "192.0.2.10");
    }
}
