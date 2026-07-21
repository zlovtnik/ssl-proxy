# ssl-proxy

![License](https://img.shields.io/badge/license-MIT-blue)

A privacy-focused transparent proxy and VPN system with wireless audit,
TiDB/TiFlash vector search, and a Redpanda-backed processing plane.

## Overview

ssl-proxy provides:

- **WireGuard VPN ingress** - UDP 443 (plain) and UDP 51820 (obfuscated) endpoints for client traffic
- **Transparent TLS interception** - Redirects TCP 80/443 through a Rust proxy with SNI-based classification and obfuscation profiles
- **Wireless audit sensor** - Monitor-mode 802.11 capture (AR9271/ath9k_htc) publishing to a Redpanda-backed sync plane
- **Octopus processing plane** - supervised Cats Effect/FS2 ingestion,
  projections, leases, outbox publishing, retention, and vector preparation
- **Atheros Search** - TiDB ANN plus normalized sparse/hybrid HTTP and gRPC query facade
- **Integration console** - Rails dashboard for device inventory, heatmaps, and sync-plane observability

## Architecture

[Architecture](docs/architecture.md)

### Key Data Flows

```text
Client -> WireGuard (UDP 443/51820) -> Transparent Proxy (TCP 3001) -> Origin
                    |
            Audit Events -> Redpanda -> Octopus -> TiDB/TiFlash
                    |
            Maintained projections -> Atheros Search -> Rails console
```

**Octopus** provides sync-plane orchestration, durable dedupe, tokenized leases,
transactional outbox publishing, and maintained projections. Topics are locked
to these meanings:

| Topic | Purpose |
|-------|---------|
| `sync.scan.request` | Proxy-to-coordinator work discovery |
| `sync.oracle.load` | Coordinator-owned Oracle load dispatch |
| `sync.oracle.result` | Coordinator-owned Oracle load outcomes |

See [docs/architecture.md](docs/architecture.md) for detailed diagrams and [docs/runbook.md](docs/runbook.md) for operational procedures. Design decisions are recorded in [docs/adr/](docs/adr/).

## Quick Start

### Prerequisites

- Docker + Docker Compose
- An external TiDB v8.5+ cluster with TiFlash, four provisioned databases, and
  TLS credentials
- A fresh external Keycloak realm/client and a Redis endpoint
- Oracle wallet (for Oracle sink) in `./wallet/`
- WireGuard peer configs for `WG_PEERS` under `config/<peer>/` (`peer1,peer2` by default)

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

For iPhone, run `make up-ready PROFILE_MODE=iphone ...` and import the selected
direct profile or QR code. The profile points at the server's plain WireGuard
frontdoor port and contains no loopback shim endpoint. Server-side obfuscation
stays enabled so an existing shim client can remain connected concurrently.

For a Linux/macOS shim client:

1. Build the obfuscation shim:
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

For obfuscated profiles, subtract obfuscation overhead from the plain WireGuard
MTU budget. The legacy XOR+magic path adds 1 byte, so the example profiles use
`1419` instead of `1420`. Framed XOR adds 41 bytes (`39` frame header + `2`
body length), and framed AEAD adds 57 bytes (`41` + `16` tag). If
`WG_OBFUSCATION_PADDING=fixed-mtu:N` or `random-bucket:...` is used, every
bucket must be large enough for the encoded frame and small enough for the path
MTU.

### Generating Peer Keys

```bash
wg genkey | tee privatekey-peer | wg pubkey > publickey-peer
# Place private key in config/<peer>/privatekey-<peer>.
```

For pre-shared keys (recommended for obfuscated peers):
```bash
wg genpsk > presharedkey-peer1
```

## Port Assignments

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| WireGuard Frontdoor | 443 | UDP | Default obfuscated shim entrypoint; probes active/candidate backends during rotation, then pins each client to the backend that replies |
| WireGuard Frontdoor | 51820 | UDP | Plain/direct WireGuard entrypoint used concurrently by iPhone profiles in the default shim deployment |
| Transparent Proxy | 3001 | TCP | Internal listener for redirected WireGuard traffic |
| Admin API + Dashboard | 3002 | TCP | Internal health, dashboard, and stats surface |
| Frontdoor Health | 3003 | TCP | Host-local health and metrics for `wg-udp-frontdoor` |
| WAHA | 3006 | TCP | Host-local WhatsApp HTTP API for rotator notifications (`rotator` profile) |
| Explicit Proxy | 3000 | TCP | Legacy opt-in listener, disabled by default |
| Coordinator Actuator | 8081 | TCP | Health/actuator (internal) |
| Integration Console | 3005 | TCP | Rails dashboard (device inventory, heatmaps) |
| Atheros Search UI | 3007 | TCP | Search, graph, and inventory UI (single-node Kubernetes) |
| External TiDB | 4000 | TCP/TLS | Four isolated runtime databases (not deployed by this repository) |
| MinIO API | 9000 | TCP | S3-compatible object storage (internal) |
| MinIO Console | 9001 | TCP | MinIO admin UI (internal) |
| Prometheus | 9090 | TCP | Metrics aggregation (observability) |
| Pushgateway | 9091 | TCP | Metrics push endpoint (observability) |
| Node Exporter | 9100 | TCP | Host metrics (observability) |
| cAdvisor | 8082 | TCP | Container metrics (observability) |
| Grafana | 3004 | TCP | Dashboards (observability) |
| Loki | 3100 | TCP | Log aggregation (observability) |
| Jaeger UI | 16686 | TCP | Distributed tracing |
| OTel gRPC | 4317 | TCP | OpenTelemetry collector gRPC |
| OTel HTTP | 4320 | TCP | OpenTelemetry collector HTTP |
| Search gRPC | 50051 | TCP | Atheros Search gRPC API (cluster-internal in Kubernetes) |
| Search HTTP | 8080 | TCP | Atheros Search REST API (proxied by the UI in Kubernetes) |

## Components

### Core Services (always running)

| Service | Description | Implementation |
|---------|-------------|----------------|
| **ssl-proxy** | Rust transparent proxy, WireGuard terminator, obfuscation engine | [src/](src/) |
| **octopus** | Scala 3 Cats Effect/FS2 owner of durable TiDB ingestion, leases, outbox, and projections | [services/octopus/](services/octopus/) |
| **integration-console** | Rails dashboard for devices, heatmaps, sync status | [apps/integration-console/](apps/integration-console/) |
| **redpanda** | Kafka-compatible event backbone for sync topics | - |
| **atheros-search** | Go TiDB dense/sparse/hybrid query facade; no background workers | [services/atheros-search/](services/atheros-search/) |
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
| **pushgateway** | Metrics push endpoint for batch jobs | 9091 |

### Vector search

| Service | Description | README |
|---------|-------------|--------|
| **Octopus processors** | Prepare/complete embeddings and maintain similarity projections | [services/octopus/](services/octopus/) |
| **atheros-search** | Go HTTP/gRPC query facade | [services/atheros-search/](services/atheros-search/) |
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
| `WG_PEERS` | `peer1,peer2` | Comma-separated peer list shared by the active proxy, rotation candidate, `up-ready`, and key rotator |
| `WG_PORT` | `443` | Public obfuscation-relay port when obfuscation is enabled; direct WireGuard port otherwise |
| `WG_INTERNAL_PORT` | `51820` | Plain boringtun listener exposed through the frontdoor for concurrent direct clients when obfuscation is enabled |
| `WG_MTU` | `1420` | WireGuard interface MTU for the plain/direct path. Obfuscated legacy XOR+magic profiles use `1419`; framed AEAD profiles need lower values based on frame overhead. |
| `WG_OBFUSCATION_MAX_DATAGRAM_BYTES` | `1500` | Maximum UDP datagram buffer used by the relay, shim, and frontdoor. Raise only when the path MTU supports larger datagrams. |
| `WG_UDP_SOCKET_BUFFER_BYTES` | `16777216` | Requested UDP send/receive socket buffer size for WireGuard relay, shim, and frontdoor sockets. |
| `WG_OBFUSCATION_ENABLED` | `false` | Enable XOR + magic byte obfuscation |
| `WG_OBFUSCATION_KEY_FILE` | `secrets/wg_obfuscation_key` via Compose mount | File-backed obfuscation key for rotated deployments |
| `WG_FRONTDOOR_CONFIG_FILE` | `secrets/wg-rotation/frontdoor/wg-udp-frontdoor.toml` via Compose mount | UDP frontdoor backend config; multiple enabled backends are probed until one replies for a client |
| `WG_FRONTDOOR_MAX_SESSIONS` | `65536` | Maximum active frontdoor client/backend UDP sessions before the oldest session is evicted |
| `WG_FRONTDOOR_RATE_LIMIT_PPS` | `0` | Optional per-source packet rate limit; `0` disables it to avoid capping normal tunnel throughput |
| `WG_FRONTDOOR_DISPATCH_TASK_LIMIT` | `4096` | Aggregate bounded dispatch queue capacity per listener before packets are dropped |
| `EXPLICIT_PROXY_ENABLED` | `false` | Enable legacy HTTP CONNECT proxy on :3000 |
| `ADMIN_API_KEY_FILE` | `secrets/admin_api_key` via Compose mount | File-backed bearer token for admin endpoints |
| `SYNC_REDPANDA_BOOTSTRAP_SERVERS` | `redpanda:9092` | Kafka bootstrap for sync plane |
| `TIDB_HOST` / `TIDB_PORT` | *(required)* | External TiDB endpoint; loopback and bundled defaults are rejected |
| `TIDB_DATABASE` | `octopus_core` | Octopus-owned database |
| `TIDB_USER` / `TIDB_PASSWORD` | *(required)* | Dedicated least-privilege Octopus account |
| `ATHSEARCH_TIDB_DSN` | *(required)* | Native MySQL DSN from a Secret for the `atheros_search` account |
| `REDIS_URL` | *(required for console)* | Ephemeral Rails cache and ActionCable fan-out only |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry collector |
| `REGISTRY` | *(required)* | Local registry host for first-party Compose images, e.g. `192.168.1.221:5000` |
| `SCHEMA_MIGRATOR_PUBLIC_HOSTNAME` | *(required for Kubernetes)* | Public DNS hostname for the Schema Migrator HTTPS origin; provide a hostname only, without `https://` |
| `ACME_EMAIL` | *(required for Kubernetes)* | Let's Encrypt account and expiry-notification email used by the Helm-owned Traefik edge |

`wg-udp-frontdoor` listener entries also support `session_idle` and `jitter_ms`
TOML fields. Keep `jitter_ms` low; `5` ms is intended for coarse timing
correlation resistance, while values above `50` ms add noticeable variance.
| `REGISTRY_PLAIN_HTTP` | `auto` | Buildx plain-HTTP registry mode; auto-detects localhost and private IPv4 registries |
| `IMAGE_TAG` | `latest` | Image tag consumed by Compose |

All four direct clients require verified TLS, dedicated non-root accounts, the
expected database name, TiDB v8.5+, and the canonical manifest checksum. Rails
uses `mysql2://` URLs for `integration_console` and its read-only core/search
connections. Schema-migrator uses `BEDROCK_STATE_DB_*` for its TiDB control
store; PostgreSQL URLs are accepted only for an explicitly configured external
migration target.

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

### Vector processing

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOPUS_PROCESSORS_ENABLED` | `false` | Enable processors only after the signed fresh-start cutover gate |
| `VECTOR_EMBEDDING_PROVIDER` | `ollama` | `ollama` or `llamacpp` |
| `VECTOR_EMBEDDING_URL` | `http://127.0.0.1:11434` | Provider endpoint |
| `VECTOR_EMBEDDING_MODEL` | `nomic-embed-text-v2-moe` | Model name |
| `VECTOR_EMBEDDING_DIMENSIONS` | `768` | Vector dimensions |
| `VECTOR_EMBEDDING_BATCH_SIZE` | `64` | Octopus embedding lease batch size |

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
| `registry-build-vec-worker` | Retired compatibility alias; do not use for runtime deployment |
| `deploy` | SSH to `DEPLOY_HOST`, pull images in `DEPLOY_PATH`, and run Compose |
| `clean` | Clean build artifacts |
| `up-ready` | Publish local-registry images, upgrade Kubernetes with Helm, verify services, and print peer QR codes |
| `diagnose` | Non-mutating diagnosis and signature classification |
| `pipeline-health` | Check sync-plane pipeline health |
| `memo-show` | Show operational memory ledger |
| `memo-log` | Append one operational incident line |
| `db-check-connections` | Verify external TiDB client connectivity and schema readiness |
| `smoke` | Run the Docker Compose smoke scenarios |
| `bench-wg-path` | Run WireGuard path iperf benchmark cases |
| `schema-migrator-smoke` | Run schema migrator list/validate/apply smoke flow |
| `prep-ath` | Prepare the Atheros capture interface |
| `setup-ubuntu` | Bootstrap Docker and start the stack on Ubuntu |
| `configure-containerd-registry` | Configure a Kubernetes node's containerd CRI pulls from a plain-HTTP `REGISTRY` |
| `shellcheck-tier-b` | Validate retained container/init shell scripts |
| `ops-test` | Run the Python operator CLI unit tests |
| `audit-threats` | Query wireless threat alerts view |

## Kubernetes Deployment

The umbrella Helm chart is at [helm/ssl-proxy/](helm/ssl-proxy/), with
service and infrastructure charts under `helm/ssl-proxy/charts/`. Shared
connection values used across chart boundaries are explicit under
`global.shared`; workload and image overrides retain paths such as
`proxy.image.tag`, `javaCoordinator.image.tag`, and
`observability.grafana.image.tag`.

The chart deploys application workloads but never deploys TiDB or Keycloak.
Configure the external TiDB endpoint, CA Secret, four account Secrets, fresh
external Keycloak issuer/clients, and Redis Secret under `global.shared`.
`global.migration.mode` is one of `stage`, `activate`, or `prune`; follow the
cutover gates in [docs/tidb-runtime-cutover.md](docs/tidb-runtime-cutover.md).

The image name remains canonical end to end: the development machine builds
`linux/amd64` and pushes to `192.168.1.221:5000`, and Kubernetes pulls the same
`192.168.1.221:5000/...` references. On each Kubernetes node, configure
containerd once before the first deployment:

```bash
make configure-containerd-registry REGISTRY=192.168.1.221:5000
```

Single-node developer values may expose application ports, but identity and
TiDB remain external. Atheros Search has no ingest, embedding, alert, or repair
worker; those supervised workloads run in Octopus.

```bash
make up-ready PROFILE_MODE=mac \
  SERVER_IP=192.168.1.221 \
  CLIENT_IP=192.168.1.53 \
  SCHEMA_MIGRATOR_PUBLIC_HOSTNAME=schema.example.com \
  ACME_EMAIL=ops@example.com
```

Before deployment, point the selected hostname at the public address that
forwards TCP 80 and 443 to `192.168.1.221`. Permit inbound TCP 80 for the ACME
HTTP-01 challenge and redirect, and TCP 443 for the application. UDP 443
remains assigned to WireGuard and does not conflict with the Schema Migrator
TCP listener. Schema Migrator control state lives only in its isolated TiDB
database; ACME state is edge configuration, not application business state.

The operator uses standard `kubectl` and `helm`. It selects
`UP_READY_KUBE_CONTEXT` when set and otherwise uses the current kubeconfig
context. Run it on the Kubernetes server or provide a working remote context.
Before Helm starts, it verifies that containerd can pull a mirrored image from
`REGISTRY`; `UP_READY_KUBE_REGISTRY_PROBE_TIMEOUT` controls the default 45-second
probe timeout. Helm upgrades use server-side apply, rollback on failure, bounded
history, Job waiting, and an explicit readiness timeout.
Use `UP_READY_DEPLOYMENT_TARGET=compose` to retain the previous Compose
workflow.

The legacy Make targets are opt-in so they do not remain interleaved with the
current operator workflow:

```bash
make ENABLE_LEGACY_TARGETS=1 legacy-diagnose
```

## Operational Scripts

| Script | Purpose |
|--------|---------|
| `ops/` (`python3 -m sslproxy_ops`) | Typed host-side operator CLI for host/operator workflows |
| `scripts/up-ready.sh` | Compatibility shim to `ops up-ready` |
| `scripts/diagnose.sh` | Compatibility shim to `ops diagnose` |
| `scripts/smoke_test.sh` | Compatibility shim to `ops schema-migrator smoke` |
| `scripts/sync-status.sh` | Compatibility shim to `ops pipeline status` |
| `scripts/deploy-and-verify.sh` | Deprecated compatibility shim to `ops up-ready` |
| `scripts/prep_ath.sh` | Compatibility shim to `ops host prep-ath` |
| `scripts/memo-show.sh` / `scripts/memo-log.sh` | Compatibility shims to `ops memo show` / `ops memo log` |

## Troubleshooting

### Common Issues

**WireGuard tunnel won't establish**
- Verify peer config files exist for every name in `WG_PEERS` under `config/<peer>/`
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

**TiDB connection or readiness refused**
- Confirm the external hostname, TLS server name/CA, dedicated account, and
  expected database.
- Verify TiDB is v8.5+ and the recorded canonical manifest checksum matches.
- Vector readiness also requires all four TiFlash replicas before HNSW DDL.

### Getting Help

- [docs/runbook.md](docs/runbook.md) - detailed operational procedures
- [docs/threat-model.md](docs/threat-model.md) - security model and assumptions
- [docs/bugs.md](docs/bugs.md) - known issues and workarounds
- [docs/ssl-proxy-compliance-audit-enhancement-workmap.md](docs/ssl-proxy-compliance-audit-enhancement-workmap.md) - compliance audit workmap
- [ops-memory.md](ops-memory.md) - operational incident ledger
