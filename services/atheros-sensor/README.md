# Atheros Sensor

`atheros-sensor` is a Linux monitor-mode Wi-Fi sensor, preferably used with an
AR9271/`ath9k_htc` adapter. It captures 802.11 frames, constructs
schema-versioned audit and alert events, publishes them through Redpanda and
keeps a bounded local backlog. It never writes PostgreSQL directly.

## Topic direction

Published topics include:

- `wireless.audit`, paired with a `sync.scan.request` whose stream is
  `wireless.audit`
- `wireless.client.inventory`
- `wireless.alert.rogue_ap`
- `wireless.alert.deauth_flood`
- `wireless.alert.attack_sequence`
- `wireless.alert.sequence`
- `wireless.alert.signal_anomaly`
- `wireless.alert.pmf_attack`
- `wireless.sensor.heartbeat`
- wireless backlog/request topics used by Octopus request/reply flows

The sensor subscribes to, rather than publishes:

- the audit-window configuration topic
- `wireless.config.authorized_networks`
- `wireless.config.sensor`

Live config subscribers support only the repository's plain raw
`redpanda://` transport. They are disabled for Kafka listeners and TLS-enabled
Redpanda connections. Publishing still uses the configured sync-plane
producer.

## Runtime configuration

Core capture settings:

| Variable | Purpose |
|---|---|
| `ATH_SENSOR_DEVICE` | Monitor-mode interface; auto-detected when empty |
| `ATH_SENSOR_LOCATION_ID` | Stable deployment location |
| `ATH_SENSOR_CHANNEL` | Initial channel |
| `ATH_SENSOR_CHANNEL_HOP_ENABLED` | Enable the default 1/6/11 hop loop |
| `ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS` | Channel dwell time |
| `ATH_SENSOR_REG_DOMAIN` | Regulatory domain |
| `ATH_SENSOR_BPF` | Capture filter |
| `ATH_SENSOR_SNAPLEN` | Capture length |
| `ATH_SENSOR_PCAP_TIMEOUT_MS` | pcap read timeout |
| `ATH_SENSOR_PIPELINE_WORKERS` | Bounded processing concurrency |
| `ATH_SENSOR_PIPELINE_QUEUE_CAPACITY` | Pipeline queue bound |
| `ATH_SENSOR_METRICS_PORT` | OpenMetrics listener |
| `ATH_SENSOR_METRICS_TEXTFILE_PATH` | Atomic node-exporter textfile output path |
| `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS` | Reject container-only endpoints in host mode |

Detection and persistence settings include the `ATH_SENSOR_CLIENT_*`,
`ATH_SENSOR_SIGNAL_*`, `ATH_SENSOR_DEAUTH_*`, `ATH_SENSOR_BACKLOG_*`,
`ATH_SENSOR_MAC_*` and `AUDIT_WINDOW_*` families.

Redpanda uses `SYNC_REDPANDA_BOOTSTRAP_SERVERS` plus the existing
`SYNC_REDPANDA_*` security settings. Secrets use the plain environment variable
first and its `_FILE` fallback second. `SYNC_OUTBOX_DIR` controls local JSON
durability.

Only BPF, channel and audit-window settings are live mutable. Other changes
require a restart.

## Host setup

```bash
make prep-ath
```

Then point the host-mode sensor at a host-reachable listener, for example:

```bash
export SYNC_REDPANDA_BOOTSTRAP_SERVERS=redpanda://127.0.0.1:19092
cargo run -p atheros-sensor
```

Compose uses `ATH_SENSOR_REDPANDA_BOOTSTRAP_SERVERS` to override the stack-wide
container-to-container bootstrap address. Monitor-mode capture requires Linux,
`NET_ADMIN`/`NET_RAW` and access to the wireless device.

## Logging, metrics and schemas

Logs are JSON on stdout/stderr. Invalid or missing `RUST_LOG` falls back to
`warn,atheros_sensor=info`. `ATH_SENSOR_LOG_IDLE_SECS` controls capture
heartbeat logs; `0` disables them. `ATH_SENSOR_AUDIT_LAYER_STREAM` is `off` by
default and should be enabled only for an intentional legacy audit mirror.

`ATH_SENSOR_METRICS_PORT` exposes `/metrics` on loopback only. The sensor also
atomically replaces `ATH_SENSOR_METRICS_TEXTFILE_PATH` (default
`/var/lib/node_exporter/textfile_collector/atheros_sensor.prom`) every 15
seconds, including a timestamp used for stale-data alerts. Do not log secrets, raw
handshakes or full identifiers beyond existing audited behavior.

Current published schema versions include `AuditEntry` version 2 and wireless
bandwidth/handshake alert version 1. Topic names and schema versions are
cross-service contracts.

## Build and verify

```bash
cargo test -p atheros-sensor
cargo clippy -p atheros-sensor -- -D warnings
cargo build -p atheros-sensor
make dependency-boundaries
```

The systemd template is [`atheros-sensor.service`](atheros-sensor.service).
Update paths, interface settings and TLS credential locations before
installation. Hardware capture still requires validation on the target Linux
host.
