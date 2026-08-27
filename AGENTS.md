# AGENTS.md

## Scope
This file governs the repository rooted at `/Users/rcs/git/ssl-proxy` and all
children, including checked-out submodules, unless a deeper `AGENTS.md`
overrides a rule for its subtree.

## Working Style
- Read the relevant code and local instructions before changing files.
- Prefer `rg` / `rg --files` for search and file discovery.
- Use `apply_patch` for manual edits. Avoid ad hoc file rewrites.
- Keep changes ASCII unless a file already uses Unicode for a clear reason.
- Do not revert, overwrite, or tidy edits you did not make.
- Assume the workspace may be dirty; stay inside the requested assignment.

## Repo Anatomy
- `src/` is the Rust `ssl-proxy` service: WireGuard ingress, transparent proxy,
  tunnel transport, admin/readiness surfaces, and proxy-side sync publishing.
- `crates/sync-plane/` contains shared Rust Redpanda publisher/config/contract
  code used by producers.
- `apps/schema-migrator/` is the Scala Cats Effect runner whose control state
  lives in the `schema_migrator` schema; it also supports external PostgreSQL
  and deprecated Oracle targets.
- `services/atheros-sensor/` is the Rust Linux monitor-mode wireless sensor.
- `services/atheros-search/` is the Go HTTP/gRPC search, vector, and ETL
  control plane service for wireless audit data. It owns embedding job
  processing via a worker pool and exposes ETL health monitoring.
- `services/octopus/` is the Scala 3 Cats Effect/FS2 coordinator and owner of
  durable ingestion, leases, outbox, and maintained PostgreSQL projections, built via sbt.
- `services/platform-sync/` is the Go host-side Vault-to-Kubernetes secret
  synchronization service. It reads all platform inputs from Vault, validates
  them, and writes Secrets and ConfigMaps to the production namespace.
- `services/` has local `AGENTS.md` files for shared service rules and
  service-specific conventions.
- `apps/wg-key-rotator/` is an Elixir WireGuard key rotation tool.
- `apps/integration-console/atheros-search-ui/` is a standalone SolidJS/Bun UI.
  It has its own local `AGENTS.md`.
- `sql/postgres/` is the canonical runtime schema source for four schemas in
  the external `sync` database: `octopus_core`, `atheros_search`,
  `schema_migrator`, and `keycloak`, plus the shared `contracts/` layer.
- `cyber-stack/base/` contains environment-neutral Kubernetes resources.
  `cyber-stack/matrix/prod/` contains the production Kustomize slices.
- `docker/`, `scripts/`, and `docs/` hold deployment, operational, and design
  material.

## Architecture Guardrails
- Keep coordinator concerns in `services/octopus/`: cursoring, dedupe,
  job state, batching, backlog handling, and PostgreSQL load/result behavior.
- Atheros Search owns embedding job processing (claim, embed, write vectors)
  via its worker pool. Projection maintenance and alert derivation remain
  Octopus concerns.
- PostgreSQL clients are intentional for Octopus, Atheros Search, and
  schema-migrator. Keep them on isolated schemas/accounts and enforce the
  table-level grant matrix in `sql/postgres/*/grants/`. Do not add direct database wiring to `src/`,
  `crates/sync-plane/`, or `services/atheros-sensor/`.
- Keep PostgreSQL connection configuration consistent between application config
  (`AppConfig.scala` PostgresConfig fields) and the production Kustomize render.
  Every PostgreSQL env var consumed by a service must have a
  corresponding ConfigMap, Secret or overlay source. When changing PostgreSQL
  connection parameters (host, port, sslMode, sslCaPath, sslServerName), update
  the application defaults and production render path in parallel.
- Preserve the locked sync topic meanings:
  - `sync.scan.request` for producer-to-coordinator work discovery
  - `sync.oracle.load` for coordinator-owned PostgreSQL load dispatch (legacy name)
  - `sync.oracle.result` for coordinator-owned PostgreSQL load outcomes (legacy name)
- Keep delivery semantics at-least-once from committed Kafka consumer-group
  offsets, with earliest-retained startup for new groups, durable PostgreSQL dedupe,
  and per-topic/partition/offset ingestion evidence.
- Keep wireless sensor persistence indirect: publish `wireless.audit` and the
  matching `sync.scan.request`; do not give the sensor direct database ownership.
- Keep `atheros-search` schema changes in repository-level `sql/` unless a
  change is truly service-local and independent.
- Keep proxy classification aligned to the current taxonomy:
  - `ads_tracker`
  - `analytics`
  - `cdn`
  - `essential_api`
  - `auth`
  - `unknown`

## Kubernetes Management
- Kubernetes desired state lives only under `cyber-stack/` and is rendered by
  Kustomize and reconciled by Argo CD from `main`.
- Change workload configuration, images, scaling, routing, policy and rollout
  order through reviewed Git changes. Do not add direct cluster mutation to
  scripts, Make targets, CI jobs or operator documentation.
- Keep reusable resources in `cyber-stack/base/` and production differences in
  `cyber-stack/matrix/prod/`. Add workloads to exactly one of `bootstrap`,
  `data-plane`, or `app-stack`.
- Keep first-party environment images pinned by digest. Production promotion
  is reviewed and never automatic.
- Treat platform-provided Secrets, registry access and the production PostgreSQL
  endpoint as prerequisite contracts. Store only names and key references in
  this repository.
- Use Argo CD sync waves/hooks for dependency order. Namespace pruning requires
  explicit confirmation. Roll back by reverting Git.
- Read-only cluster inspection is allowed for diagnosis. Do not repair drift by
  editing, patching, scaling or restarting managed resources interactively.

## Change Rules
- Keep Rust changes localized and deliberate; preserve the sensor/proxy
  dependency boundary enforced by `make dependency-boundaries`.
- Treat active PostgreSQL migrations and ordered schema additions as append-only unless
  a task explicitly asks for a replacement. Do not revive the retired
  `sql/postgres/core/` baseline or PostgreSQL runtime aggregates.
- Treat the four domain manifests under `sql/postgres/` (and the shared
  `contracts/` layer) as authoritative. Only the provisioning schema executor
  may apply DDL; application runtimes verify the recorded manifest checksums
  and fail closed.
- PostgreSQL is the only stack runtime database. MongoDB and other database
  fallbacks are not allowed.
- Preserve API contracts, Redpanda payload shapes, schema-versioned wireless
  events, and UI data contracts unless the user asks for a contract change.
- Avoid introducing new dependencies unless they clearly earn their keep.
- Do not edit generated, runtime, or environment-specific files such as
  `target/`, `.gradle/`, `.omx/`, `node_modules/`, `dist/`, `secrets/`, or
  `wallet/` unless the task explicitly requires it.
- If you do touch generated or environment-specific files, say so plainly.

## Local Development
- Database integration tests use ephemeral PostgreSQL Testcontainers.

## Verification
- Run the smallest meaningful checks for the files you changed.
- Prefer targeted tests over broad suites when possible.
- Useful root checks:
  - `cargo test -p ssl-proxy`
  - `cargo test -p sync-plane`
  - `cargo test -p atheros-sensor`
  - `cd apps/schema-migrator && sbt test`
  - `cd services/octopus && sbt test`
  - `make dependency-boundaries`
  - `make atheros-search-test`
  - `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`
  - `make lint`
  - `make test` for a broad repository pass
- If a check cannot be run, state the blocker and the risk.
- Do not claim success without evidence from a command, test, build, or review.

## Review Discipline
- Call out correctness, security, and regression risks first.
- Keep feedback concrete: file, line, behavior, impact.
- If a fix has tradeoffs, name them rather than smoothing them over.

## House Rules
- Respect existing conventions before inventing new ones.
- Keep commits, branches, and filenames boring where possible.
- When the codebase is loud, answer with precision.

## Documentation Maintenance
- Every `.md` file must have valid cross-references. If a referenced file, directory,
  service, or env var does not exist, fix the reference or remove the dead content.
- Historical/superseded documents must carry a status blockquote at the top
  (`> **Status: Historical / superseded.**`) and a one-line warning after the first
  heading stating that the body contains references to retired files, services, or
  technologies.
- AGENTS.md files must not duplicate rules from their parent. Each subtree file should
  contain only service-specific rules. If a rule appears in both a parent and child
  AGENTS.md, remove it from the child.
- When adding or removing a service, update the root AGENTS.md Repo Anatomy section
  and the relevant subtree AGENTS.md in the same change.
- When adding a new AGENTS.md, keep it under 60 lines. If it exceeds that, split the
  excess into a companion README.
- Do not mix YAML agent definitions (opencode config, persona blocks) into AGENTS.md.
  Agent config belongs in `.opencode/` or a dedicated config file.
- Verify documentation with `python3 scripts/check-docs.py` after changes.
