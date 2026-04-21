# Atheros Sensor

`atheros-sensor` is a Linux host-side Wi-Fi monitor that captures AR9271 management
and data frames, enriches them with sensor metadata and identity hints, and publishes them into the existing
sync-plane used by this repository.

## Runtime Model

- Runs on a Linux host with direct access to the AR9271 interface.
- Reuses the repo's NATS and Postgres stack through `SYNC_NATS_URL` and `DATABASE_URL`.
- Publishes the raw audit payload on subject `wireless.audit`.
- Publishes a matching `sync.scan.request` message with `stream_name=wireless.audit`.
- Falls back to Postgres `audit_backlog` rows when NATS is unavailable.

## Environment

- `ATH_SENSOR_DEVICE`
- `ATH_SENSOR_LOCATION_ID`
- `ATH_SENSOR_CHANNEL`
- `ATH_SENSOR_REG_DOMAIN`
- `ATH_SENSOR_BPF`
- `ATH_SENSOR_SNAPLEN`
- `ATH_SENSOR_PCAP_TIMEOUT_MS`
- `ATH_SENSOR_LOG_IDLE_SECS`
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
- `DATABASE_URL`
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

`ATH_SENSOR_LOG_IDLE_SECS` controls the capture heartbeat interval. The default
is `30`, which emits periodic logs with packet, decoded-frame, drop, and error
counters while capture is open. Set it to `0` to disable the heartbeat.

## Host Setup

1. Put the AR9271 interface into monitor mode with [`scripts/prep_ath.sh`](/Users/rcs/git/ssl-proxy/scripts/prep_ath.sh).
2. Point the sensor at the compose stack:
   - `SYNC_NATS_URL=nats://127.0.0.1:4222`
   - `DATABASE_URL=postgres://sync:sync@127.0.0.1:5432/sync`
3. Start the service directly or install the provided `systemd` unit template.

Default capture filter is `type mgt or type data`. Override `ATH_SENSOR_BPF` when
you need a narrower packet profile.

## systemd

The unit template lives at [atheros-sensor.service](/Users/rcs/git/ssl-proxy/services/atheros-sensor/atheros-sensor.service).

Update `ExecStart`, the interface environment, and any TLS credential paths before
installing it on a host.
