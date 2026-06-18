# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services/atheros-sensor`.

## Project Shape
- Rust 2021 workspace package `atheros-sensor`.
- Runtime target is a Linux host with monitor-mode Wi-Fi hardware, preferably
  AR9271/`ath9k_htc`.
- `src/config.rs` is environment-variable-only configuration. Secrets use the
  plain env var first and the `_FILE` fallback second.
- `src/capture.rs`, `src/parse/`, and `src/audit/` own packet capture,
  802.11 parsing, and audit event construction.
- `src/publish.rs`, `src/backlog/`, and `src/topics.rs` own Redpanda publish,
  circuit-breaker, local backlog, and topic behavior.
- `src/config_subscriber.rs` and `src/channel_control.rs` own runtime sensor
  config and channel switching.

## Guardrails
- Keep the sensor as a sync-plane producer only. It publishes Redpanda events
  and matching `sync.scan.request` work; it must not write Postgres directly or
  talk to Oracle.
- Preserve the two-tier persistence strategy: Redpanda first, coordinator
  backlog/request fallback, then local JSONL durability where implemented.
- Keep `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS` behavior intact for host-mode
  deployments.
- Preserve runtime-mutability boundaries documented in `src/config.rs`: BPF,
  channel, and audit window may update from config pushes; most other settings
  require restart.
- Treat topic names in `src/topics.rs` and schema versions in emitted payloads
  as cross-service contracts.
- Keep capture paths resilient to malformed frames, missing radiotap metadata,
  Redpanda outages, and channel-hop races.
- Do not log secrets, raw handshakes, or full identifiers beyond existing
  audited behavior.

## Commands
- Run sensor tests from the repository root: `cargo test -p atheros-sensor`.
- Lint sensor code: `cargo clippy -p atheros-sensor -- -D warnings`.
- Build sensor: `cargo build -p atheros-sensor`.

## Verification
- Run targeted Rust tests for changed modules when possible, then
  `cargo test -p atheros-sensor`.
- Run `make dependency-boundaries` if dependencies or workspace edges change.
- Hardware capture behavior may require manual Linux host validation; state that
  clearly when local tests cannot cover it.
