# ssl-proxy

An advanced transparent proxy for enterprise network deployments, built in Rust
on BoringTun and WireGuard. It combines encrypted VPN ingress, traffic policy
enforcement and observable egress without per-application proxy configuration.

BoringTun provides userspace WireGuard connectivity. Linux policy routing
directs tunneled TCP traffic through the transparent proxy, which classifies
connections and applies policy before forwarding to the original destination.

## Capabilities

- **Transparent traffic control:** Linux TPROXY, TLS ClientHello/SNI inspection,
  hostname classification, blocklists and fail-closed handling for HTTPS
  connections without SNI by default.
- **WireGuard transport:** BoringTun interface control, peer telemetry,
  optional packet obfuscation, client shims and staged key-rotation tooling.
- **Protected administration:** API-key authentication, MFA claim checks,
  authentication rate limits and a loopback-bound admin listener by default.
- **Operational visibility:** health and readiness endpoints, Prometheus
  metrics, structured audit events and OpenTelemetry tracing.
- **Controlled execution:** startup configuration validation, bounded
  connections and graceful shutdown; optional explicit HTTP CONNECT and
  HTTP/3 CONNECT listeners.
- **Event integration:** Redpanda publishing through the shared
  [`sync-plane`](crates/sync-plane/) crate. Octopus owns durable ingestion and
  PostgreSQL persistence; the proxy has no direct database connection.

Traffic classification is heuristic. TLS inspection uses handshake metadata;
encrypted application payloads remain opaque on the transparent path. See the
[threat model](docs/threat-model.md) for path-specific guarantees and limits.

## Get started

Clone the workspace, including its nested repositories, then build the proxy:

```bash
git clone --recurse-submodules https://github.com/zlovtnik/ssl-proxy.git
cd ssl-proxy
cargo build --release --locked -p ssl-proxy
```

Use Rust/Cargo and the native build prerequisites recorded in the
[`Dockerfile`](Dockerfile). For an existing checkout, initialize nested
repositories with `git submodule update --init --recursive`.

Running the proxy requires Linux networking, a configured WireGuard interface,
TUN access and routing/firewall rules. The
[container entrypoint](docker/entrypoint.sh) provisions the BoringTun interface
and network rules; starting the Rust binary alone does not establish a routed
VPN. Client profiles and transport examples are in [`config/client/`](config/client/),
[`config/peer1/`](config/peer1/), [`config/peer2/`](config/peer2/) and
[`config/frontdoor/`](config/frontdoor/).

## Configuration

The proxy reads and validates environment variables at startup. Supply an admin
key of at least 32 bytes through `ADMIN_API_KEY` or `ADMIN_API_KEY_FILE`.
WireGuard obfuscation is enabled by default and also requires a key of at least
32 bytes through `WG_OBFUSCATION_KEY` or `WG_OBFUSCATION_KEY_FILE`.

| Setting | Default | Purpose |
|---|---|---|
| `TPROXY_PORT` | `3001` | Transparent TCP ingress |
| `EXPLICIT_PROXY_ENABLED` | `false` | Enable the explicit proxy listener |
| `PROXY_PORT` | `3000` | Explicit proxy port when enabled |
| `ADMIN_BIND_ADDR` / `ADMIN_PORT` | `127.0.0.1` / `3002` | Administration, `/health`, `/ready` and `/metrics` |
| `MAX_CONNECTIONS` | `4096` | Concurrent proxy connection limit |

Full configuration lives in [`src/config_sections/`](src/config_sections/).
Production values and secret references live in the
[proxy manifests](cyber-stack/base/proxy/) and
[production patch](cyber-stack/matrix/prod/patches/proxy.yaml).

## Deployment and verification

Kubernetes desired state lives in [`cyber-stack/`](cyber-stack/), rendered by
Kustomize and reconciled by Argo CD from `main`. Production images are pinned
by digest and promoted through reviewed Git changes. Follow the
[GitOps guide](cyber-stack/README.md) and [operations runbook](docs/runbook.md)
for deployment, diagnostics and rollback.

Run the checks relevant to proxy changes:

```bash
cargo test --locked -p ssl-proxy
cargo test --locked -p sync-plane
make dependency-boundaries
make docs-check
make gitops-check
```

## Companion services

The workspace includes supporting ingestion, retrieval and operational tools.
Each has its own documentation and deployment requirements.

| Component | Responsibility |
|---|---|
| [Octopus](services/octopus/README.md) | Durable ingestion, dedupe, coordination and PostgreSQL projections |
| [Atheros Sensor](services/atheros-sensor/README.md) | Wireless observations published through Redpanda |
| [Atheros Search](apps/integration-console/README.md) | Evidence retrieval, embedding workers and the authenticated console |
| [DQ](services/dq/README.md) | Isolated data-quality processing and its workspace |
| [Octopus Metrics](services/octopus-metrics/README.md) / [Stats Reader](services/stats-reader/README.md) | Snapshot materialization and public metrics delivery |
| [Platform Sync](services/platform-sync/README.md) | Vault-to-Kubernetes configuration and secret synchronization |
| [Schema Migrator](apps/schema-migrator/README.md) | Database migration review and execution |
| [WireGuard key rotator](apps/wg-key-rotator/README.md) | Staged peer and server key rotation |
| [Product site](apps/product-site/README.md) | Public project hub and synthetic demonstrations |

See the [system architecture](docs/architecture.md) for service boundaries and
data contracts, [secret management](docs/secret-management.md) for credential
handling, and [observability](docs/observability-architecture-jaeger.md) for
telemetry integration.
