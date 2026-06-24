# ssl-proxy

![License](https://img.shields.io/badge/license-MIT-blue)

A privacy-focused transparent proxy and VPN system with wireless audit capabilities, vector embeddings for device intelligence, and Oracle-backed audit persistence.

## Overview

ssl-proxy provides:

- **WireGuard VPN ingress** - UDP 443 (plain) and UDP 51820 (obfuscated) endpoints for client traffic
- **Transparent TLS interception** - Redirects TCP 80/443 through a Rust proxy with SNI-based classification and obfuscation profiles
- **Wireless audit sensor** - Monitor-mode 802.11 capture (AR9271/ath9k_htc) publishing to a Redpanda-backed sync plane
- **Vector embeddings worker** - PostgreSQL-only embedding pipeline for device behaviour, frame sequences, and infrastructure graphs
- **Oracle sink in the Java coordinator** - At-least-once delivery of classified audit events to Oracle ADB
- **Integration console** - Rails dashboard for device inventory, heatmaps, and sync-plane observability

## Architecture

[Architecture](docs/architecture.md)

### Key Data Flows

```text
Client -> WireGuard (UDP 443/51820) -> Transparent Proxy (TCP 3001) -> Origin
                    |
            Audit Events -> Redpanda -> Coordinator (x3) -> Oracle ADB
                    |
            PostgreSQL -> Vec Worker -> Embeddings (pgvector) -> Similarity Search
```

The **coordinator** (3 replicas for HA) provides sync-plane job orchestration: cursoring, deduplication, batch dispatch, and result handling. Topics are locked to these meanings:

| Topic | Purpose |
|-------|---------|
| `sync.scan.request` | Proxy-to-coordinator work discovery |
| `sync.oracle.load` | Coordinator-owned Oracle load dispatch |
| `sync.oracle.result` | Coordinator-owned Oracle load outcomes |

See [docs/architecture.md](docs/architecture.md) for detailed diagrams and [docs/runbook.md](docs/runbook.md) for operational procedures. Design decisions are recorded in [docs/adr/](docs/adr/).

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Oracle wallet (for Oracle sink) in `./wallet/`
- WireGuard peer configs in `config/peer1/`, `config/peer2/`

### Start the stack

```bash
# 1. Generate local stack secrets and materialize .env
scripts/gen-secrets generate
scripts/gen-secrets env

# Save secrets/ONE_TIME_TOKENS outside the repo, then delete it.

# 2. Start all services with local developer builds
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build

# 3. Verify health
curl -i http://127.0.0.1:3002/health
```

For pull-only server deployments from the local registry, see
[docs/local-registry-workflow.md](docs/local-registry-workflow.md).

### WireGuard Client Setup

1. Build the obfuscation shim (Linux/macOS):
   ```bash
   cargo build --release -p wg-obfs-shim
   ```

2. Import `config/peer1/peer1-obfuscated.conf.example` into your WireGuard client:
   - Address: `10.13.13.2/32`
   - DNS: `10.13.13.1`
   - Endpoint: `127.0.0.1:51821` (local shim)
   - AllowedIPs: `0.0.0.0/0, ::/0`

3. Configure the real server endpoint in `config/client/wg-obfs-shim.env.example`

**Do not** combine this with a manual HTTP proxy on the client - WireGuard is the primary ingress path.

### Generating Peer Keys

```bash
wg genkey | tee privatekey-peer | wg pubkey > publickey-peer
# Place private key in config/peer1/ and config/peer2/ respectively
```

For pre-shared keys (recommended for obfuscated peers):
```bash
wg genpsk > presharedkey-peer1
```

## Port Assignments

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| WireGuard Frontdoor | 443 | UDP | Stable public UDP entrypoint, fanned out to active/candidate backends during rotation |
| WireGuard Frontdoor | 51820 | UDP | Stable alternate public UDP entrypoint for obfuscated Mac/shim profiles |
| Transparent Proxy | 3001 | TCP | Internal listener for redirected WireGuard traffic |
| Admin API + Dashboard | 3002 | TCP | Internal health, dashboard, and stats surface |
| Frontdoor Health | 3003 | TCP | Host-local health and metrics for `wg-udp-frontdoor` |
| WAHA | 3006 | TCP | Host-local WhatsApp HTTP API for rotator notifications (`rotator` profile) |
| Explicit Proxy | 3000 | TCP | Legacy opt-in listener, disabled by default |
| Coordinator Actuator | 8081 | TCP | Health/actuator (internal) |
| Integration Console | 3005 | TCP | Rails dashboard (device inventory, heatmaps) |
| Redis | 6379 | TCP | Caching and job queues (internal) |
| MinIO API | 9000 | TCP | S3-compatible object storage (internal) |
| MinIO Console | 9001 | TCP | MinIO admin UI (internal) |
| Postgres | 5432 | TCP | Primary state store (internal) |
| Postgres Exporter | 9187 | TCP | Postgres metrics (observability) |
| Redis Exporter | 9121 | TCP | Redis metrics (observability) |
| Prometheus | 9090 | TCP | Metrics aggregation (observability) |
| Pushgateway | 9091 | TCP | Metrics push endpoint (observability) |
| Node Exporter | 9100 | TCP | Host metrics (observability) |
| cAdvisor | 8082 | TCP | Container metrics (observability) |
| Grafana | 3004 | TCP | Dashboards (observability) |
| Loki | 3100 | TCP | Log aggregation (observability) |
| Jaeger UI | 16686 | TCP | Distributed tracing |
| OTel gRPC | 4317 | TCP | OpenTelemetry collector gRPC |
| OTel HTTP | 4320 | TCP | OpenTelemetry collector HTTP |
| Search gRPC | 50051 | TCP | Atheros Search gRPC API (vector profile) |
| Search HTTP | 8080 | TCP | Atheros Search REST API (vector profile) |

## Components

### Core Services (always running)

| Service | Description | Implementation |
|---------|-------------|----------------|
| **ssl-proxy** | Rust transparent proxy, WireGuard terminator, obfuscation engine | [src/](src/) |
| **coordinator** | Java sync control plane plus Oracle ADB sink - cursoring, dedupe, job state, batching, wallet-backed Oracle loads. 3 replicas for HA. | [services/zig-coordinator/](services/zig-coordinator/) (Gradle/Java) |
| **integration-console** | Rails dashboard for devices, heatmaps, sync status | [apps/integration-console/](apps/integration-console/) |
| **redpanda** | Kafka-compatible event backbone for sync topics | - |
| **postgres** | Primary state store (sync_events, devices, vec_embeddings, etc.) | [sql/postgres.sql](sql/postgres.sql) |
| **redis** | Caching and job queues for integration console | - |
| **minio** | S3-compatible object store (console exports) | - |

### Observability Stack

| Service | Description | Port |
|---------|-------------|------|
| **otel-collector** | OpenTelemetry collector (traces + metrics) | 4317/4320 |
| **prometheus** | Metrics aggregation and alerting | 9090 |
| **grafana** | Dashboards for all observability signals | 3004 |
| **loki** | Log aggregation | 3100 |
| **promtail** | Docker log shipping to Loki | - |
| **jaeger** | Distributed tracing UI | 16686 |
| **cadvisor** | Container resource metrics | 8082 |
| **node-exporter** | Host-level metrics | 9100 |
| **postgres-exporter** | Postgres query performance metrics | 9187 |
| **redis-exporter** | Redis metrics | 9121 |
| **pushgateway** | Metrics push endpoint for batch jobs | 9091 |

### Vector Profile (optional, `docker compose --profile vector up`)

| Service | Description | README |
|---------|-------------|--------|
| **vec-worker** | PostgreSQL-only embedding worker (Ollama/llama.cpp) | [services/vec-worker/README.md](services/vec-worker/README.md) |
| **atheros-search** | Go gRPC search service for wireless audit embeddings | [services/atheros-search/](services/atheros-search/) |
| **ollama** | Local embedding model server | - |

### Rotator Profile (optional)

The `rotator` profile runs WAHA and the containerized WireGuard key rotator. WAHA is bound to `http://127.0.0.1:${WAHA_HOST_PORT:-3006}` on the host, while the rotator container calls it at `http://waha:3000`. Run these commands from the repository root, or set `ROTATOR_REPO_ROOT` to the absolute checkout path.

```bash
docker compose --profile rotator up -d waha
docker compose --profile rotator run --rm wg-key-rotator status
docker compose --profile rotator run --rm wg-key-rotator rotate --scheduled
```

### Wireless Sensor (host-mode, optional)

| Service | Description | README |
|---------|-------------|--------|
| **atheros-sensor** | Linux monitor-mode Wi-Fi capture (AR9271 preferred) | [services/atheros-sensor/README.md](services/atheros-sensor/README.md) |

## Traffic Classification

The proxy classifies destinations and applies obfuscation profiles per domain:

### Classification Labels

| Label | Meaning |
|-------|---------|
| `ads_tracker` | Advertising and tracking domains |
| `analytics` | Analytics and telemetry endpoints |
| `cdn` | Content delivery networks (pass-through) |
| `essential_api` | Critical API endpoints (pass-through) |
| `auth` | Authentication and identity providers |
| `unknown` | Unclassified (default) |

### Active Obfuscation Profiles

- **fox-news**: Fox News domain family
- **fox-sports**: Fox Sports domain family

### Applied Modifications

**Request Headers**
- Removes `X-Forwarded-For`, `Via`, `Forwarded` proxy headers
- Strips `DNT`, `Sec-GPC` privacy signals
- Normalizes User-Agent to configured standard value

**Response Headers**
- Removes `X-Cache`, `X-Edge-IP`, `X-Served-By` CDN leak headers
- Preserves security headers (CSP, HSTS)

Domain matching supports wildcard subdomains and is case-insensitive.

## Configuration

### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_INTERFACE_NAME` | `wg0` | WireGuard interface name |
| `WG_PORT` | `443` | Plain WireGuard UDP port |
| `WG_INTERNAL_PORT` | `51820` | Obfuscated WireGuard UDP port |
| `WG_OBFUSCATION_ENABLED` | `false` | Enable XOR + magic byte obfuscation |
| `WG_OBFUSCATION_KEY_FILE` | `secrets/wg_obfuscation_key` via Compose mount | File-backed obfuscation key for rotated deployments |
| `WG_FRONTDOOR_CONFIG_FILE` | `secrets/wg-rotation/frontdoor/wg-udp-frontdoor.toml` via Compose mount | UDP frontdoor backend config |
| `EXPLICIT_PROXY_ENABLED` | `false` | Enable legacy HTTP CONNECT proxy on :3000 |
| `ADMIN_API_KEY_FILE` | `secrets/admin_api_key` via Compose mount | File-backed bearer token for admin endpoints |
| `SYNC_REDPANDA_BOOTSTRAP_SERVERS` | `redpanda:9092` | Kafka bootstrap for sync plane |
| `DATABASE_URL` | Compose default: `jdbc:postgresql://postgres:5432/sync` | Primary Postgres connection. PostgreSQL credentials are supplied separately as `POSTGRES_USER=sync` and the generated `POSTGRES_PASSWORD`; URL-style values must follow `postgres://sync:${POSTGRES_PASSWORD}@postgres:5432/sync` when credentials are embedded. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry collector |
| `REGISTRY` | *(required)* | Local registry host for first-party Compose images, e.g. `192.168.1.221:5000` |
| `REGISTRY_PLAIN_HTTP` | `auto` | Buildx plain-HTTP registry mode; auto-detects localhost and private IPv4 registries |
| `IMAGE_TAG` | `latest` | Image tag consumed by Compose |

The coordinator resolves the database URL in `DataSourceConfig.java` by
preferring `JDBC_DATABASE_URL`, then `DATABASE_URL`, then
`spring.datasource.url`, and finally `jdbc:postgresql://localhost:5432/sync`.
If the selected URL does not embed credentials, it falls back to
`POSTGRES_USER=sync` and `POSTGRES_PASSWORD`. In the Compose network the
expected components are host `postgres`, port `5432`, database `sync`, and user
`sync`.

### Rotator Profile

| Variable | Default | Description |
|----------|---------|-------------|
| `WAHA_HOST_PORT` | `3006` | Host-local port for WAHA dashboard/API |
| `WAHA_IMAGE` | `devlikeapro/waha` | WAHA Core image; use `devlikeapro/waha:arm` for native ARM |
| `WAHA_PLATFORM` | `linux/amd64` | Default platform for the Core image; use `linux/arm64` with the ARM image |
| `WAHA_NO_API_KEY` | `False` | Keep WAHA API-key auth enabled |
| `WAHA_CHAT_ID` | *(empty)* | WhatsApp chat ID for rotation notifications |
| `WAHA_API_KEY` | Generated by `scripts/gen-secrets env` | WAHA API key, also sent by the rotator |
| `WAHA_SESSION` | `default` | WAHA session name used by rotator notifications |
| `ROTATOR_REPO_ROOT` | current shell `PWD` | Absolute repo path mounted into the rotator container; set explicitly if not running compose from the repo root |

### Oracle Sink (requires auto-login wallet in `./wallet/`)

| Variable | Description |
|----------|-------------|
| `ORACLE_CONN` | TNS alias (e.g., `mainerc_high`) |
| `ORACLE_USER` | Oracle username |
| `ORACLE_PASS_FILE` | Path to password file (e.g., `/run/secrets/oracle_password.txt`) |
| `TNS_ADMIN` | Wallet directory (`/app/wallet`) |
| `ORACLE_SINK_ENABLED` | Enable coordinator-owned Oracle loads (`true` by default) |

The coordinator validates `tnsnames.ora`, `sqlnet.ora`, `cwallet.sso`, the `ORACLE_CONN` alias, and a non-empty password file before opening the Oracle pool. `scripts/gen-secrets` creates `secrets/oracle_password.txt`; for a real Oracle ADB user, replace that file with the actual `ORACLE_USER` password before enabling the sink.

### Vector Worker

| Variable | Default | Description |
|----------|---------|-------------|
| `VECTOR_EMBEDDINGS_ENABLED` | `true` | Enable embedding pipeline |
| `VECTOR_EMBEDDING_PROVIDER` | `ollama` | `ollama` or `llamacpp` |
| `VECTOR_EMBEDDING_URL` | `http://127.0.0.1:11434` | Provider endpoint |
| `VECTOR_EMBEDDING_MODEL` | `nomic-embed-text-v2-moe` | Model name |
| `VECTOR_EMBEDDING_DIMENSIONS` | `768` | Vector dimensions |
| `VECTOR_EMBEDDING_BATCH_SIZE` | `64` | Jobs leased per iteration |

### Wireless Sensor

| Variable | Default | Description |
|----------|---------|-------------|
| `ATH_SENSOR_DEVICE` | *auto* | Wireless interface (e.g., `wlxc01c3038d5e8`) |
| `ATH_SENSOR_CHANNEL` | `11` | 802.11 channel for monitor mode |
| `ATH_SENSOR_CHANNEL_HOP_ENABLED` | `false` | Enable channel hopping |
| `ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS` | `1000` | Milliseconds between channel hops |
| `ATH_SENSOR_REG_DOMAIN` | `US` | Regulatory domain |
| `ATH_SENSOR_LOCATION_ID` | `default` | Sensor location label |
| `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS` | `true` | Fail if host endpoints unavailable |
| `ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED` | `true` | Enable MAC OUI vendor lookup |
| `ATH_SENSOR_CLIENT_INVENTORY_FLUSH_SECS` | `60` | Client inventory flush interval |
| `ATH_SENSOR_SIGNAL_ANOMALY_DBM_DELTA` | `15` | Signal anomaly threshold (dBm) |
| `ATH_SENSOR_DEAUTH_FLOOD_THRESHOLD` | `20` | Deauth flood detection count |
| `ATH_SENSOR_DEAUTH_FLOOD_WINDOW_SECS` | `30` | Deauth flood detection window |
| `ATH_SENSOR_DEAUTH_FLOOD_COOLDOWN_SECS` | `60` | Cooldown between deauth alerts |
| `ATH_SENSOR_EXPORT_HANDSHAKES` | `false` | Export 4-way handshake frames |
| `ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_TTL_SECS` | `60` | Authorized network cache TTL |
| `ATH_SENSOR_SHUTDOWN_GRACE_SECS` | `5` | Grace period on shutdown |
| `ATH_SENSOR_BACKLOG_MAX_ATTEMPTS` | `10` | Max retry attempts for send failures |
| `ATH_SENSOR_BACKLOG_MAX_AGE_HOURS` | `72` | Max age for backlogged frames |
| `ATH_SENSOR_REDPANDA_REQUEST_TIMEOUT_MS` | `10000` | Redpanda produce timeout |
| `ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS` | `30` | MAC lookup error cache TTL |
| `ATH_SENSOR_AUDIT_LAYER_STREAM` | `off` | Enable audit layer stream (`off`/`meta`/`full`) |

## Makefile Reference

| Target | Description |
|--------|-------------|
| `build` | Build Rust proxy, atheros-sensor, and Java coordinator binaries |
| `test` | Run all test suites |
| `bench` | Run local benchmark baselines (`wg_packet_obfuscation`) |
| `lint` | Run `cargo clippy -- -D warnings` |
| `docker` | Build selected local Docker images through `docker-compose.build.yaml` |
| `registry-buildx` | Create or use the registry-aware buildx builder |
| `registry-build-all` | Build and push linux/amd64 registry images |
| `registry-build-vec-worker` | Build vec-worker when its Dockerfile exists; otherwise fail clearly |
| `deploy` | SSH to `DEPLOY_HOST`, pull images in `DEPLOY_PATH`, and run Compose |
| `clean` | Clean build artifacts |
| `up-ready` | Bring up compose stack, verify services, print peer QR codes |
| `diagnose` | Non-mutating diagnosis and signature classification |
| `pipeline-health` | Check sync-plane pipeline health |
| `memo-show` | Show operational memory ledger |
| `memo-log` | Append one operational incident line |
| `audit-threats` | Query wireless threat alerts view |

## Kubernetes Deployment

A Helm chart is available at [helm/ssl-proxy/](helm/ssl-proxy/):

```bash
helm upgrade --install ssl-proxy ./helm/ssl-proxy \
  --set proxy.adminApiKey=your-key \
  --set postgres.password=sync
```

## Operational Scripts

| Script | Purpose |
|--------|---------|
| `scripts/up-ready.sh` | Bring up stack, verify all services, print QR codes, and write `secrets/up-ready-credentials.txt` |
| `scripts/diagnose.sh` | Non-mutating diagnosis of proxy and tunnel state |
| `scripts/smoke_test.sh` | End-to-end smoke test |
| `scripts/sync-status.sh` | Pipeline health check (sync plane) |
| `scripts/deploy-and-verify.sh` | Full deploy + verification workflow |
| `scripts/prep_ath.sh` | Atheros sensor interface preparation |
| `scripts/memo-show.sh` / `scripts/memo-log.sh` | Operational memory ledger |

## Troubleshooting

### Common Issues

**WireGuard tunnel won't establish**
- Verify peer config files exist in `config/peer1/` and `config/peer2/`
- Check that server private key exists locally: `config/server/privatekey-server`
- Check `wg-udp-frontdoor` health on `http://127.0.0.1:3003/health`
- Ensure UDP ports 443 and 51820 are reachable from the client

**Admin API returns 401**
- Set `ADMIN_API_KEY_FILE` to a readable file or set `ADMIN_API_KEY` to a non-empty value
- Pass it as `Authorization: Bearer <key>` header

**Oracle sink not delivering events**
- Verify the auto-login Oracle wallet is mounted in `./wallet/` with `tnsnames.ora`, `sqlnet.ora`, and `cwallet.sso`
- Check `secrets/oracle_password.txt` exists and is non-empty
- Confirm `ORACLE_CONN` TNS alias matches the wallet configuration, default `mainerc_high`
- Check `docker compose logs java-coordinator` for Oracle load failures

**Postgres connection refused**
- Postgres may still be initializing (can take 15-30s on first boot)
- Check `docker compose logs postgres` for startup progress

### Getting Help

- [docs/runbook.md](docs/runbook.md) - detailed operational procedures
- [docs/threat-model.md](docs/threat-model.md) - security model and assumptions
- [docs/bugs.md](docs/bugs.md) - known issues and workarounds
- [docs/ssl-proxy-compliance-audit-enhancement-workmap.md](docs/ssl-proxy-compliance-audit-enhancement-workmap.md) - compliance audit workmap
- [ops-memory.md](ops-memory.md) - operational incident ledger
