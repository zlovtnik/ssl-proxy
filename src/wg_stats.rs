//! WireGuard peer polling and bandwidth sampling.

use std::time::Instant;

use chrono::{TimeZone, Utc};
use tracing::{debug, info, warn};

use crate::{
    boringtun_control,
    state::{ResolvedMeta, SharedState, WgPeerSnapshot},
};

pub fn spawn_wg_stats_poller(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        let interface = state
            .config
            .wireguard
            .interface
            .clone()
            .unwrap_or_else(|| "wg0".to_string());
        let interval_secs = state.config.runtime.bandwidth_sample_interval_secs.max(1);

        info!(%interface, interval_secs, "WireGuard stats poller started");
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("WireGuard stats poller shutting down");
                    return;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)) => {}
            }

            let dump = match read_wg_dump(&interface).await {
                Ok(dump) => dump,
                Err(err) => {
                    warn!(%interface, %err, "failed to read WireGuard dump");
                    continue;
                }
            };

            let peers = parse_wg_show_dump(&dump, &interface);
            state.refresh_wg_peers(&peers);
        }
    });
}

async fn read_wg_dump(interface: &str) -> Result<String, std::io::Error> {
    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || {
        boringtun_control::dump_interface(&interface)
            .map_err(|err| std::io::Error::other(err.to_string()))
    })
    .await
    .map_err(|err| std::io::Error::other(err.to_string()))?
}

#[allow(dead_code)]
fn delta_with_reset(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

pub fn parse_wg_show_dump(dump: &str, interface: &str) -> Vec<WgPeerSnapshot> {
    dump.lines()
        .enumerate()
        .skip(1)
        .filter_map(|(_idx, line)| {
            let parts: Vec<_> = line.split('\t').collect();
            if parts.len() < 8 {
                debug!(%line, "skipping malformed wg dump line");
                return None;
            }

            let allowed_ips: Vec<String> = parts[3]
                .split(',')
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_string())
                .collect();
            let peer_ip = allowed_ips
                .iter()
                .find_map(|entry| entry.split_once('/').map(|(ip, _)| ip.to_string()))
                .or_else(|| allowed_ips.first().cloned());

            Some(WgPeerSnapshot {
                interface: interface.to_string(),
                wg_pubkey: parts[0].to_string(),
                endpoint: (!parts[2].is_empty()).then(|| parts[2].to_string()),
                allowed_ips,
                peer_ip,
                last_handshake_at: parse_handshake(parts[4]),
                rx_bytes_total: parts[5].parse::<u64>().unwrap_or(0),
                tx_bytes_total: parts[6].parse::<u64>().unwrap_or(0),
            })
        })
        .collect()
}

fn parse_handshake(value: &str) -> Option<String> {
    let epoch = value.parse::<i64>().ok()?;
    if epoch <= 0 {
        return None;
    }
    Some(Utc.timestamp_opt(epoch, 0).single()?.to_rfc3339())
}

pub async fn reverse_ptr_lookup(state: &SharedState, peer_ip: &str) -> Option<String> {
    const TTL_SECS: u64 = 300;
    if let Some(entry) = state.ptr_cache.get(peer_ip) {
        if entry.fresh(TTL_SECS) {
            return entry.ptr_hostname.clone();
        }
    }

    let parsed_ip = peer_ip.parse().ok()?;
    let hostname = state
        .resolver
        .reverse_lookup(parsed_ip)
        .await
        .ok()
        .and_then(|lookup| lookup.iter().next().map(|name| name.to_utf8()));

    state.ptr_cache.insert(
        peer_ip.to_string(),
        ResolvedMeta {
            resolved_at: Instant::now(),
            resolved_ips: vec![peer_ip.to_string()],
            ptr_hostname: hostname.clone(),
            asn_org: None,
        },
    );

    hostname
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wg_dump_rows() {
        let dump = "priv\tpub\t51820\toff\npeerkey\tpsk\t198.51.100.10:443\t10.13.13.2/32\t1713225600\t10\t20\t25\n";
        let peers = parse_wg_show_dump(dump, "wg0");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].wg_pubkey, "peerkey");
        assert_eq!(peers[0].peer_ip.as_deref(), Some("10.13.13.2"));
        assert_eq!(peers[0].rx_bytes_total, 10);
        assert_eq!(peers[0].tx_bytes_total, 20);
    }

    #[test]
    fn delta_handles_counter_reset() {
        assert_eq!(delta_with_reset(20, 10), 10);
        assert_eq!(delta_with_reset(5, 10), 5);
    }
}
