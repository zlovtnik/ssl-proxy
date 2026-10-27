# Atheros Search / ssl-proxy workspace

Atheros Search is an ingestion-backed evidence retrieval workbench for RAG
builders and operators. One authenticated SolidJS console and Search API join
retrieval, ingestion visibility, source readiness, evidence exploration and the
existing DQ workspace. The Rust proxy and Linux Atheros Sensor publish
observations; Scala Octopus owns durable ingestion, document preparation and
maintained projections; Go Search owns ranking, authenticated application APIs
and fenced embedding execution. The repository retains the `ssl-proxy` name
for the workspace and proxy component.

This is Rafael Cardoso dos Santos's independently maintained backend and
data-platform portfolio. Start with the [Atheros Search walkthrough](https://rclabs.uk/atheros-search/)
and trace the producer, coordinator, and query boundaries below. Schema
Migrator is companion tooling for database change review. Public browser samples
are synthetic; deployment readings do not establish customer outcomes or a
service-level commitment.

Observed identifiers and similarity candidates do not establish physical device
identity. Traffic classification is heuristic and depends on the configured
path. Collection scope and remaining risks are described in the
[threat model](docs/threat-model.md).

## Component ownership

| Component | Responsibility | Documentation |
|---|---|---|
| `ssl-proxy` | WireGuard ingress, transparent proxying, classification and sync publishing | [Architecture](docs/architecture.md) |
| `sync-plane` | Shared Redpanda producer configuration, payload references, bounded publishing and disk spooling | [`crates/sync-plane/`](crates/sync-plane/) |
| Atheros Sensor | Monitor-mode wireless capture and indirect persistence through Redpanda | [Sensor README](services/atheros-sensor/README.md) |
| Octopus | Durable ingestion, dedupe, evidence, leases, batching, outbox, PostgreSQL load/results and maintained projections | [Octopus README](services/octopus/README.md) |
| Atheros Search | Ingestion-backed retrieval: Go ranking/evidence and operational read APIs, fenced embedding workers and the SolidJS workbench | [Project README](apps/integration-console/README.md) |
| DQ | Database-free processor admission, isolated workers and a SolidJS workspace; Octopus owns durable runs | [DQ README](services/dq/README.md) |
| Octopus Metrics | C++23 snapshot materializer with read-only PostgreSQL access; publishes Redis/MinIO snapshots | [Metrics README](services/octopus-metrics/README.md) |
| Stats Reader | Go public snapshot reader with Redis/MinIO fallback and no database or broker access | [Stats Reader README](services/stats-reader/README.md) |
| Platform Sync | Host-side Go service that validates Vault inputs and updates Git-created Kubernetes Secret/ConfigMap shells | [Platform Sync README](services/platform-sync/README.md) |
| Schema Migrator | Migration authoring/execution and PostgreSQL-backed internal control state | [Schema Migrator README](apps/schema-migrator/README.md) |
| WireGuard key rotator | Staged WireGuard key rotation and optional notifications | [Rotator README](apps/wg-key-rotator/README.md) |
| Product site | Astro/SolidJS public hub with synthetic Search/Migrator demos and a runtime metrics feed | [Product site README](apps/product-site/README.md) |

`java-coordinator` remains an image and Kubernetes resource identity for the
Octopus service. Likewise, `sync.oracle.load` and `sync.oracle.result` are
locked legacy topic names; both carry coordinator-owned PostgreSQL work and results.

## Data boundaries

Canonical DDL lives in [`sql/postgres/`](sql/postgres/) for four schemas in the
external `sync` database:

- `octopus_core`
- `atheros_search`
- `schema_migrator`
- `keycloak`

The Integration Console browser and DQ processes are database-free. Octopus,
Atheros Search, Schema Migrator and Keycloak use separate PostgreSQL roles;
Octopus Metrics has read-only access. The provisioning schema executor applies
the canonical manifests; Octopus, Atheros Search and Schema Migrator verify
their recorded checksums and fail closed on mismatch. Oracle remains deprecated
external target compatibility in Schema Migrator, not a stack runtime dependency.

## Get started

Start with the [source-to-retrieval workflow](docs/atheros-search-workflow.md)
for console navigation, readiness limits and operational access. Retrieval
returns evidence and explanations; generated answers and new connectors are
outside this release. Schema Migrator remains companion tooling with its own
change-review workflow.

Clone the complete workspace, including its nested repositories:

```bash
git clone --recurse-submodules https://github.com/zlovtnik/ssl-proxy.git
cd ssl-proxy
```

For an existing checkout, run `git submodule update --init --recursive`.
The Search and Migrator servers depend on the canonical schemas and deployment
contracts in this parent repository. Their individual checkouts are not a
self-contained hosted stack.

For a database-free review, run the [public site locally](apps/product-site/README.md#local-development)
or use the [Migrator offline commands](apps/schema-migrator/README.md#cli).
The site uses synthetic samples. Migrator dry-run output is shortened; retain
the complete SQL source beside it. Its catalog drift comparison does not cover
column definitions or nullability.

Run the targeted tests for the components you change. Validate all canonical
GitOps inputs with:

```bash
make docs-check
make gitops-check
```

Publish the twelve images in the Kubernetes image contract to the repositories
selected by the canonical environment (`prod` by default), then compare their
pushed digests with the committed pins:

```bash
make publish ENV=prod
```

Jenkins, component publishing, and the Compose-only key rotator retain
`make publish-all REGISTRY=registry.example.com`. HTTPS is the default.
`REGISTRY_PLAIN_HTTP=1` is an explicit option for an isolated local registry;
it does not provide authenticated, encrypted transport. Publishing changes registry
tags only; it does not mutate Git or a cluster. Diagnose desired and live state
read-only with `make stack-health`; it uses the active Kubernetes
context unless `KUBE_CONTEXT` is explicitly set. Record
new digests with the printed `make bump-digest-<service>` commands and record
component acceptance evidence in the production promotion pull request. The
repository has no development Kubernetes overlay; use component test harnesses
for local validation. See the [GitOps guide](cyber-stack/README.md)
and [operations runbook](docs/runbook.md).

## Local development

Install only the toolchains needed by your component: Rust/Cargo for the proxy
and sensor, JDK/sbt for Scala services, Go for Search/DQ/platform helpers,
Node or Bun as specified by each frontend, and CMake with a C++23 compiler for
Octopus Metrics. Use each component README for its exact versions and commands.
Root documentation checks require Python 3; GitOps checks also require PyYAML
and `kustomize`.

Database integration tests use ephemeral PostgreSQL 16 Testcontainers. No
development database Compose stack is bundled; the repository-managed Wiretrap
host prerequisite is documented in [the PostgreSQL host guide](docs/postgres-host.md).

```bash
(cd services/octopus && sbt test)
(cd apps/schema-migrator && sbt test)
```

Production readiness is determined from the production Argo CD Applications.

### Proxy configuration and client tooling

The Rust proxy reads environment variables, validates them at startup, and
requires an admin key of at least 32 bytes through `ADMIN_API_KEY` or
`ADMIN_API_KEY_FILE`. Configuration is defined in
[`src/config_sections/`](src/config_sections/); production values and key
references are supplied by the [proxy manifests](cyber-stack/base/proxy/)
and [production patch](cyber-stack/matrix/prod/patches/proxy.yaml).

Transparent ingress uses `TPROXY_PORT` (default `3001`); the explicit proxy is
disabled by default and uses `PROXY_PORT` (`3000`) when enabled. The admin
listener uses `ADMIN_PORT` (`3002`) and provides `/health`, `/ready` and
`/metrics`; protected admin routes also require the configured authentication
and MFA claims. Linux routing, WireGuard and firewall prerequisites are in the
[operations runbook](docs/runbook.md). Starting the binary alone does not
establish a routed VPN.

The workspace also builds `wg-obfs-shim` and `wg-udp-frontdoor`. Client examples
live in [`config/client/`](config/client/),
[`config/peer1/`](config/peer1/) and [`config/peer2/`](config/peer2/);
the frontdoor example is in [`config/frontdoor/`](config/frontdoor/).
Review the [threat model](docs/threat-model.md) before selecting a traffic path.

## Topic contracts

| Topic | Current meaning |
|---|---|
| `sync.scan.request` | Producer-to-Octopus work discovery |
| `sync.oracle.load` | Octopus-owned PostgreSQL load dispatch; legacy name |
| `sync.oracle.result` | Octopus-owned PostgreSQL load outcome; legacy name |
| `wireless.audit` | Sensor-published schema-versioned wireless events |
| `proxy.payload_audit` | Proxy payload-audit records ingested by Octopus as scan requests |

Octopus also consumes wireless operational topics. Backlog listing and pruning,
MAC lookup, and authorized-network operations have request/reply contracts;
backlog save, mark-synced, probe-flush, and other remaining operations are
one-way unless a reply topic is explicitly provisioned. See the [Octopus
README](services/octopus/README.md) for consumer groups, DLQ suffixes, and the
`OCTOPUS_CONSUMERS_ENABLED` gate.

Delivery is at least once from committed Kafka consumer-group offsets, with durable PostgreSQL
dedupe and topic/partition/offset evidence.

Trim is irreversible. If a consumer group is added, it must exist before its
first run or it can lose unread data. See the [Redpanda daily maintenance
runbook](docs/runbooks/redpanda-maintenance.md).

## Common checks

Run these from the workspace root; choose the checks for the affected component.

| Scope | Check |
|---|---|
| Proxy / shared producer / sensor | `cargo test -p ssl-proxy`, `cargo test -p sync-plane`, `cargo test -p atheros-sensor` |
| Producer dependency boundaries | `make dependency-boundaries` |
| Octopus | `(cd services/octopus && sbt test)` |
| Schema Migrator | `(cd apps/schema-migrator && sbt test)` |
| Atheros Search | `make atheros-search-test` and `make atheros-search-ui-check` |
| DQ | `(cd services/dq && go test ./...)` |
| Octopus Metrics | `make octopus-metrics-test` |
| Stats Reader / Platform Sync | `(cd services/stats-reader && go test ./...)`, `(cd services/platform-sync && go test ./...)` |
| Product site | `(cd apps/product-site && npm run build && npm test)` |
| WireGuard key rotator | `(cd apps/wg-key-rotator && mix test)` |
| Repository scripts | `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v` |
| Documentation / desired state | `make docs-check`, `make gitops-check` |

## Operational references

- [GitOps management and onboarding](cyber-stack/README.md)
- [Jenkins image CI](docs/jenkins-ci.md)
- [System architecture](docs/architecture.md)
- [Atheros reporting workmap](docs/atheros-reporting-workmap.md)
- [Reporting data and relationship contract](docs/atheros-reporting-data-contract.md)
- [Operations runbook](docs/runbook.md)
- [Redpanda daily maintenance](docs/runbooks/redpanda-maintenance.md)
- [Atheros Search degraded mode](docs/runbooks/atheros-search-degraded.md)
- [Observability architecture](docs/observability-architecture-jaeger.md)
- [Secret management](docs/secret-management.md)
- [Threat model](docs/threat-model.md)
