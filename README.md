# ssl-proxy

![License](https://img.shields.io/badge/license-MIT-blue)

ssl-proxy is a WireGuard-first transparent proxy with wireless audit,
Redpanda-backed processing, TiDB persistence and vector search. The Rust proxy
and Linux Atheros Sensor publish events; the Scala Octopus coordinator owns
durable ingestion and maintained projections; the Go Atheros Search service
owns query APIs and embedding workers; and the SolidJS Atheros Search UI is the
Integration Console.

The canonical runtime model, data ownership and known deployment gaps are in
[System Architecture](docs/architecture.md).

## Choose a deployment path

| Path | Use it for | Entry point | Status |
|---|---|---|---|
| Compose compatibility | Local development, compatibility testing and service inspection | [`docker-compose.yaml`](docker-compose.yaml) | Bundles single-process TiDB/UniStore; not a production TiFlash topology |
| Umbrella Helm | Current single-release Kubernetes workflow | [`helm/ssl-proxy/`](helm/ssl-proxy/) and `make up-ready` | Default operational path; exact values determine enabled services |
| stackctl split releases | Dependency-ordered, opt-in Kubernetes rollout | [`stackctl/`](stackctl/) and `make up-ready-stackctl` | Opt in until split-release acceptance is complete |

WireGuard ports are profile dependent. The Compose frontdoor declares UDP
`443` for the obfuscated/direct frontdoor path and UDP `51820` for concurrent
plain clients. The proxy admin surface is host-local on `3002`. Kubernetes
host ports depend on the selected values overlay; render the chart rather than
copying a global port table.

## Component ownership

| Component | Responsibility | Documentation |
|---|---|---|
| `ssl-proxy` | WireGuard ingress, transparent proxying, classification and sync publishing | [Architecture](docs/architecture.md) |
| `sync-plane` | Shared Redpanda producer configuration and contracts | [`crates/sync-plane/`](crates/sync-plane/) |
| Atheros Sensor | Monitor-mode wireless capture and indirect persistence through Redpanda | [Sensor README](services/atheros-sensor/README.md) |
| Octopus | Durable ingestion, dedupe, evidence, leases, batching, outbox, TiDB load/results and maintained projections | [Octopus README](services/octopus/README.md) |
| Atheros Search | HTTP/gRPC search, ETL health, embedding-job claims and vector writes | [Search README](services/atheros-search/README.md) |
| Integration Console | SolidJS UI for Search, graph, inventory and ETL health | [`atheros-search-ui`](apps/integration-console/atheros-search-ui/) |
| Schema Migrator | Migration authoring/execution and TiDB-backed internal control state | [Schema Migrator README](apps/schema-migrator/README.md) |
| WireGuard key rotator | Staged WireGuard key rotation and optional notifications | [Rotator README](apps/wg-key-rotator/README.md) |

`java-coordinator` remains in Compose, Helm and image names as a legacy
deployment identity for Octopus. Likewise, `sync.oracle.load` and
`sync.oracle.result` are locked legacy topic names; both now carry
coordinator-owned TiDB work and results.

## Data boundaries

Canonical DDL lives in [`sql/tidb/`](sql/tidb/) for four application databases:

- `octopus_core`
- `atheros_search`
- `integration_console`
- `schema_migrator`

The Helm deployment also creates a separate Keycloak database. PostgreSQL is
supported only as an external Schema Migrator target. Oracle is deprecated
compatibility or historical material, not a current runtime dependency.

## Get started

Initialize every nested repository first:

```bash
git submodule update --init --recursive
```

Validate the documentation and repository checkout without starting services:

```bash
make docs-check
```

For the current Kubernetes workflow, prepare the local registry and required
secrets, then run:

```bash
make up-ready \
  PROFILE_MODE=iphone \
  SERVER_IP=192.0.2.10 \
  REGISTRY=192.0.2.10:5000
```

Use real addresses and review the [local registry workflow](docs/local-registry-workflow.md),
[secret management](docs/secret-management.md), and [runbook](docs/runbook.md)
before deployment. `PROFILE_MODE=iphone` uses the direct WireGuard profile;
Linux/macOS shim clients use the obfuscated profile and local shim endpoint.

For local image builds with Compose:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```

The Compose file is a compatibility topology and still contains known
configuration gaps. Read the [architecture known gaps](docs/architecture.md#known-gaps)
before treating a green container health check as end-to-end readiness.

## Topic contracts

| Topic | Current meaning |
|---|---|
| `sync.scan.request` | Producer-to-Octopus work discovery |
| `sync.oracle.load` | Octopus-owned TiDB load dispatch; legacy name |
| `sync.oracle.result` | Octopus-owned TiDB load outcome; legacy name |
| `wireless.audit` | Sensor-published schema-versioned wireless events |

Delivery is at least once after the signed cutover boundary, with durable TiDB
dedupe and topic/partition/offset evidence.

## Common checks

Run the smallest relevant check for a change:

```bash
cargo test -p ssl-proxy
cargo test -p sync-plane
cargo test -p atheros-sensor
make atheros-search-test
(cd services/octopus && sbt test)
(cd apps/schema-migrator && sbt test)
make dependency-boundaries
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
make docs-check
```

## Operational references

- [System architecture](docs/architecture.md)
- [Operations runbook](docs/runbook.md)
- [TiDB runtime and cutover](docs/tidb-runtime-cutover.md)
- [Observability architecture](docs/observability-architecture-jaeger.md)
- [Secret management](docs/secret-management.md)
- [Threat model](docs/threat-model.md)
- [Helm chart](helm/ssl-proxy/README.md)
- [Operations CLI](ops/README.md)
- [stackctl](stackctl/README.md)

Historical ADRs and workmaps remain under [`docs/`](docs/) for provenance.
Their status banners identify superseded guidance.
