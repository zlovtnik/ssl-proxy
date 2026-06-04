# ssl-proxy

A privacy-focused transparent proxy and VPN system with wireless audit capabilities, vector embeddings for device intelligence, and Oracle-backed audit persistence.

## Overview

ssl-proxy provides:

- **WireGuard VPN ingress** — UDP 443 (plain) and UDP 51820 (obfuscated) endpoints for client traffic
- **Transparent TLS interception** — Redirects TCP 80/443 through a Rust proxy with SNI-based classification and obfuscation profiles
- **Wireless audit sensor** — Monitor-mode 802.11 capture (AR9271/ath9k_htc) publishing to a Redpanda-backed sync plane
- **Vector embeddings worker** — PostgreSQL-only embedding pipeline for device behaviour, frame sequences, and infrastructure graphs
- **Oracle sink worker** — At-least-once delivery of classified audit events to Oracle ADB
- **Integration console** — Rails dashboard for device inventory, heatmaps, and sync-plane observability

## Architecture

![Architecture](docs/architecture.md)

Key data flows:

```
Client → WireGuard (UDP 443/51820) → Transparent Proxy (TCP 3001) → Origin
                    ↓
            Audit Events → Redpanda → Java Coordinator → Oracle Worker → Oracle ADB
                    ↓
            PostgreSQL → Vec Worker → Embeddings (pgvector) → Similarity Search
```

See [docs/architecture.md](docs/architecture.md) for detailed diagrams and [docs/runbook.md](docs/runbook.md) for operational procedures.

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Oracle wallet (for Oracle sink) in `./wallet/`
- WireGuard peer configs in `config/peer1/`, `config/peer2/`

### Start the stack

```bash
# 1. Place Oracle password
mkdir -p secrets
echo "your-oracle-password" > secrets/oracle_password.txt

# 2. Start all services
docker compose up -d

# 3. Verify health
curl -i http://127.0.0.1:3002/health
```

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

**Do not** combine this with a manual HTTP proxy on the client — WireGuard is the primary ingress path.

## Port Assignments

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| WireGuard VPN | 443 | UDP | Plain iPhone/direct tunnel endpoint |
| WireGuard Relay | 51820 | UDP | Obfuscated Mac/shim tunnel endpoint |
| Transparent Proxy | 3001 | TCP | Internal listener for redirected WireGuard traffic |
| Admin API + Dashboard | 3002 | TCP | Internal health, dashboard, and stats surface |
| Explicit Proxy | 3000 | TCP | Legacy opt-in listener, disabled by default |
| Java Coordinator | 8081 | TCP | Actuator/health (internal) |
| Atheros Search gRPC | 50051 | TCP | Search API (vector profile) |
| Atheros Search HTTP | 8080 | TCP | REST API (vector profile) |
| Prometheus | 9090 | TCP | Metrics (non-vector profile) |
| Grafana | 3004 | TCP | Dashboards (non-vector profile) |
| Jaeger UI | 16686 | TCP | Distributed tracing |
| OTel gRPC | 4319 | TCP | OpenTelemetry collector |
| OTel HTTP | 4320 | TCP | OpenTelemetry HTTP |

## Components

### Core Services (always running)

| Service | Description | README |
|---------|-------------|--------|
| **ssl-proxy** | Rust transparent proxy, WireGuard terminator, obfuscation engine | [src/](src/) |
| **java-coordinator** | Sync control plane (Kotlin/Spring/Camel) — cursoring, dedupe, job state, batching | [services/zig-coordinator/](services/zig-coordinator/) |
| **oracle-worker** | Oracle ADB sink for `proxy.events` audit stream | [services/oracle-worker/](services/oracle-worker/) |
| **integration-console** | Rails dashboard for devices, heatmaps, sync status | [apps/integration-console/README.md](apps/integration-console/README.md) |
| **redpanda** | Kafka-compatible event backbone for sync topics | — |
| **postgres** | Primary state store (sync_events, devices, vec_embeddings, etc.) | [sql/postgres.sql](sql/postgres.sql) |

### Vector Profile (optional, `docker compose --profile vector up`)

| Service | Description | README |
|---------|-------------|--------|
| **vec-worker** | PostgreSQL-only embedding worker (Ollama/llama.cpp) | [services/vec-worker/README.md](services/vec-worker/README.md) |
| **atheros-search** | Go gRPC search service for wireless audit embeddings | [services/atheros-search/](services/atheros-search/) |
| **ollama** | Local embedding model server | — |

### Wireless Sensor (host-mode, optional)

| Service | Description | README |
|---------|-------------|--------|
| **atheros-sensor** | Linux monitor-mode Wi-Fi capture (AR9271 preferred) | [services/atheros-sensor/README.md](services/atheros-sensor/README.md) |

## Configuration

### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_INTERFACE_NAME` | `wg0` | WireGuard interface name |
| `WG_PORT` | `443` | Plain WireGuard UDP port |
| `WG_INTERNAL_PORT` | `51820` | Obfuscated WireGuard UDP port |
| `WG_OBFUSCATION_ENABLED` | `false` | Enable XOR + magic byte obfuscation |
| `EXPLICIT_PROXY_ENABLED` | `false` | Enable legacy HTTP CONNECT proxy on :3000 |
| `ADMIN_API_KEY` | *required* | Bearer token for admin endpoints |
| `SYNC_REDPANDA_BOOTSTRAP_SERVERS` | `redpanda:9092` | Kafka bootstrap for sync plane |
| `DATABASE_URL` | `postgres://sync:sync@postgres:5432/sync` | Primary Postgres connection |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry collector |

### Oracle Worker (requires wallet in `./wallet/`)

| Variable | Description |
|----------|-------------|
| `ORACLE_CONN` | TNS alias (e.g., `mainerc_high`) |
| `ORACLE_USER` | Oracle username |
| `ORACLE_PASS_FILE` | Path to password file (e.g., `/run/secrets/oracle_password.txt`) |
| `TNS_ADMIN` | Wallet directory (`/app/wallet`) |

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
| `ATH_SENSOR_CHANNEL`