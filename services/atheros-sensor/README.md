# Atheros Sensor

`atheros-sensor` is a Linux host-side Wi-Fi monitor that captures monitor-mode
management and data frames (AR9271/`ath9k_htc` preferred), enriches them with sensor metadata and identity hints, and publishes them into the existing
sync-plane used by this repository.

## Runtime Model

- Runs on a Linux host with direct access to a monitor-capable Wi-Fi interface (AR9271 preferred).
- Uses NATS through `SYNC_NATS_URL`; the zig-coordinator owns all Postgres access.
- Publishes the raw audit payload on subject `wireless.audit`.
- Publishes a matching `sync.scan.request` message with `stream_name=wireless.audit`.
- Asks the coordinator to persist `audit_backlog` rows when NATS publish paths fail.

## Environment

- `ATH_SENSOR_DEVICE`
- `ATH_SENSOR_LOCATION_ID`
- `ATH_SENSOR_CHANNEL`
- `ATH_SENSOR_CHANNEL_HOP_ENABLED`
- `ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS`
- `ATH_SENSOR_REG_DOMAIN`
- `ATH_SENSOR_BPF`
- `ATH_SENSOR_SNAPLEN`
- `ATH_SENSOR_PCAP_TIMEOUT_MS`
- `ATH_SENSOR_LOG_IDLE_SECS`
- `ATH_SENSOR_CLIENT_INVENTORY_FLUSH_SECS`
- `ATH_SENSOR_SIGNAL_ANOMALY_DBM_DELTA`
- `ATH_SENSOR_DEAUTH_FLOOD_THRESHOLD`
- `ATH_SENSOR_DEAUTH_FLOOD_WINDOW_SECS`
- `ATH_SENSOR_DEAUTH_FLOOD_COOLDOWN_SECS`
- `ATH_SENSOR_EXPORT_HANDSHAKES`
- `ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_TTL_SECS`
- `ATH_SENSOR_NATS_REQUEST_TIMEOUT_MS`
- `ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED`
- `ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS`
- `ATH_SENSOR_METRICS_PORT`
- `ATH_SENSOR_SHUTDOWN_GRACE_SECS`
- `ATH_SENSOR_AUDIT_LAYER_STREAM`
- `AUDIT_WINDOW_TZ`
- `AUDIT_WINDOW_DAYS`
- `AUDIT_WINDOW_START`
- `AUDIT_WINDOW_END`
- `SYNC_NATS_URL`
- `SYNC_NATS_USERNAME`
- `SYNC_NATS_PASSWORD` or `SYNC_NATS_PASSWORD_FILE`
- `SYNC_NATS_TLS_ENABLED`
- `SYNC_NATS_TLS_SERVER_NAME`
- `SYNC_NATS_TLS_CA_CERT_PATH`
- `SYNC_NATS_TLS_CLIENT_CERT_PATH`
- `SYNC_NATS_TLS_CLIENT_KEY_PATH`
- `SYNC_INLINE_PAYLOAD_MAX_BYTES`
- `SYNC_OUTBOX_DIR`
- `RUST_LOG`

## Logging

The sensor writes JSON logs to stdout/stderr for Docker and systemd collection.
If `RUST_LOG` is missing or invalid, it falls back to:

```text
warn,atheros_sensor=info,ssl_proxy=info
```

When running through Docker Compose, override the sensor log filter with
`ATH_SENSOR_RUST_LOG`; compose maps it to the container's `RUST_LOG`. Direct
binary and systemd runs should set `RUST_LOG` directly.

`AUDIT_WINDOW_TZ` defaults to `America/New_York`.

`ATH_SENSOR_LOG_IDLE_SECS` controls the capture heartbeat interval. The default
is `30`, which emits periodic logs with packet, decoded-frame, drop, and error
counters while capture is open. Set it to `0` to disable the heartbeat.

`ATH_SENSOR_CHANNEL_HOP_ENABLED=true` cycles capture across 2.4 GHz channels
`1`, `6`, and `11`. `ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS` controls the dwell
time and the sensor reapplies the active BPF filter after each channel switch.
5 GHz and 6 GHz are parsed from radiotap metadata when present, but are not in
the default hop list.

`ATH_SENSOR_METRICS_PORT` enables an OpenMetrics endpoint at `/metrics`.
Counters include packet, decode, capture, pipeline, and MAC lookup failure
counts.

`ATH_SENSOR_AUDIT_LAYER_STREAM` defaults to `off`. Set it to `stdout` or
`stderr` only when you want the legacy audit-trace mirror in addition to the
normal JSON tracing logs.

Published event schemas use explicit `schema_version` fields where payloads can
evolve independently. Current versions are `AuditEntry.schema_version=2` and
`WirelessBandwidthEvent`/`HandshakeAlert` `schema_version=1`.

Additional subjects emitted by this sensor:

- `wireless.client.inventory`
- `wireless.alert.rogue_ap`
- `wireless.alert.deauth_flood`
- `wireless.alert.attack_sequence`
- `wireless.config.authorized_networks`
- `wireless.config.sensor`

## Host Setup

1. Put the capture interface into monitor mode with [`scripts/prep_ath.sh`](/Users/rcs/git/ssl-proxy/scripts/prep_ath.sh).
2. Point the sensor at the compose stack:
   - `SYNC_NATS_URL=nats://127.0.0.1:4222`
3. Start the service directly or install the provided `systemd` unit template.

Default capture filter is `type mgt or type data`. Override `ATH_SENSOR_BPF` when
you need a narrower packet profile.

## systemd

The unit template lives at [atheros-sensor.service](/Users/rcs/git/ssl-proxy/services/atheros-sensor/atheros-sensor.service).

Update `ExecStart`, the interface environment, and any TLS credential paths before
installing it on a host.
