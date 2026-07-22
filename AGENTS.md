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
  lives in TiDB; PostgreSQL remains supported only as an external target dialect.
- `services/atheros-sensor/` is the Rust Linux monitor-mode wireless sensor.
- `services/atheros-search/` is the Go HTTP/gRPC search, vector, and ETL
  control plane service for wireless audit data. It owns embedding job
  processing via a worker pool and exposes ETL health monitoring.
- `services/octopus/` is the Scala 3 Cats Effect/FS2 coordinator and owner of
  durable ingestion, leases, outbox, and maintained TiDB projections, built via sbt.
- `services/` has local `AGENTS.md` files for shared service rules and
  service-specific conventions.
- `apps/integration-console/atheros-search-ui/` is a standalone SolidJS/Bun UI.
  It has its own local `AGENTS.md`.
- `sql/tidb/` is the canonical runtime schema source for the three isolated
  `octopus_core`, `atheros_search`, and
  `schema_migrator` databases. PostgreSQL SQL belongs only to the historical
  archive or schema-migrator external-target fixtures.
- `helm/ssl-proxy/` is the umbrella chart; deployable units live under
  `helm/ssl-proxy/charts/`, while only shared ConfigMaps and the shared service
  account remain in the umbrella templates.
- `docker/`, `scripts/`, and `docs/` hold deployment, operational, and design
  material.

## Architecture Guardrails
- Keep coordinator concerns in `services/octopus/`: cursoring, dedupe,
  job state, batching, backlog handling, and TiDB load/result behavior.
- Atheros Search owns embedding job processing (claim, embed, write vectors)
  via its worker pool. Projection maintenance and alert derivation remain
  Octopus concerns.
- Direct TiDB clients are intentional for Octopus, Atheros Search, and
  schema-migrator. Keep them on isolated databases/accounts and
  enforce the table-level grant matrix documented in
  `docs/tidb-runtime-cutover.md`. Do not add direct database wiring to `src/`,
  `crates/sync-plane/`, or `services/atheros-sensor/`.
- Keep TiDB connection configuration consistent between application config
  (`AppConfig.scala` TiDbConfig fields) and the Helm chart values. Every TiDB
  env var consumed by a service must have a corresponding Helm value source in
  the chart's deployment template. When changing TiDB connection parameters
  (host, port, sslMode, sslCaPath, sslServerName), update both the application
  config defaults and the chart's `global.shared.tidb` values and per-chart env
  vars in parallel.
- Preserve the locked sync topic meanings:
  - `sync.scan.request` for producer-to-coordinator work discovery
  - `sync.oracle.load` for coordinator-owned TiDB load dispatch (legacy name)
  - `sync.oracle.result` for coordinator-owned TiDB load outcomes (legacy name)
- Keep delivery semantics at-least-once after the signed cutover offset, with
  durable TiDB dedupe and per-topic/partition/offset ingestion evidence.
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

## Change Rules
- Keep Rust changes localized and deliberate; preserve the sensor/proxy
  dependency boundary enforced by `make dependency-boundaries`.
- Treat active TiDB migrations and ordered schema additions as append-only unless
  a task explicitly asks for a replacement. Do not revive the retired
  `sql/tidb/core/` baseline or PostgreSQL runtime aggregates.
- Treat the four domain manifests under `sql/tidb/` as authoritative. Only the
  provisioning schema executor may apply DDL; application runtimes verify the
  recorded manifest checksums and fail closed.
- Keep PostgreSQL libraries/configuration limited to schema-migrator's explicit
  external-target implementation and tests. Runtime Helm, Compose, monitoring,
  secrets, and application fallbacks must remain PostgreSQL/MongoDB-free outside
  the one-release `helm/ssl-proxy/cutover-compat/` stage/activate assets.
- Preserve API contracts, Redpanda payload shapes, schema-versioned wireless
  events, and UI data contracts unless the user asks for a contract change.
- Avoid introducing new dependencies unless they clearly earn their keep.
- Do not edit generated, runtime, or environment-specific files such as
  `target/`, `.gradle/`, `.omx/`, `node_modules/`, `dist/`, `secrets/`, or
  `wallet/` unless the task explicitly requires it.
- If you do touch generated or environment-specific files, say so plainly.

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
