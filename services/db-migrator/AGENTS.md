# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services/db-migrator`.

## Project Shape
- Rust 2021 workspace package `db-migrator`.
- The tool discovers and applies ordered SQL files from the repository `sql/`
  directory.
- `src/discovery.rs` owns folder ordering and special cron/materialized-view
  sequencing.
- `src/schema_control.rs` owns schema manifest hashing, advisory locking,
  apply logging, and readiness state.
- `src/executor.rs` and `src/audit.rs` own execution and validation behavior.

## Guardrails
- Preserve deterministic ordering. Current folder order is extensions, schemas,
  types, tables, indexes, functions, views, cron pre-apply hooks,
  materialized_views, then cron jobs.
- Keep SQL application idempotent and retry-safe. Do not weaken schema-control
  hashing, advisory locking, or apply-log behavior.
- Avoid `--continue-on-error` as a default operational path; it is an explicit
  escape hatch.
- When adding split SQL objects, keep the aggregate bootstrap files in the root
  `sql/` tree aligned with discovery order.
- Keep validation useful without requiring a live database where possible.

## Commands
- Run tests: `cargo test -p db-migrator`.
- Validate SQL from the repo root: `cargo run -p db-migrator -- --sql-dir sql validate`.
- List discovered SQL order: `cargo run -p db-migrator -- --sql-dir sql list`.
- Dry-run apply: `cargo run -p db-migrator -- --sql-dir sql --dry-run apply`.

## Verification
- Run `cargo test -p db-migrator` after migrator changes.
- Run `validate` or `list` when changing discovery, validation, or root SQL
  ordering.
- If schema-control behavior changes, include tests for both first-apply and
  unchanged-object skip behavior.
