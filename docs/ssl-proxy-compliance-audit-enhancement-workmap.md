# SSL Proxy — Compliance & Audit Enhancement Workmap

> **Branch:** `develop`
> **Project:** `ssl-proxy`
> **Scope:** Compliance-grade audit persistence, intelligent blocklist infrastructure, transaction-level user data capture, and bandwidth/performance hardening.

---

## Table of Contents

1. [Overview](#overview)
2. [Threat Model (Initial Draft)](./threat-model.md)
3. [Execution Mode (How We’ll Run This)](#execution-mode)
4. [Epic 1 — Transaction-Level Audit & User Session Tracking](#epic-1)
5. [Epic 2 — Intelligent Blocklist Infrastructure](#epic-2)
6. [Epic 3 — Compliance Data Capture & Scraping Audit](#epic-3)
7. [Epic 4 — Bandwidth & Performance Hardening](#epic-4)
8. [Epic 5 — Observability & Alerting](#epic-5)
9. [Cross-Cutting Concerns](#cross-cutting)
10. [Milestone Schedule](#milestones)
11. [First Sprint Backlog (Let’s Rock)](#first-sprint)
12. [Architecture Decisions Record (ADR)](#adr)

---

## Overview

The proxy today provides basic tunnel open/close events and a single-URL blocklist fetched on a 24-hour cadence. As a private corporate proxy, compliance requirements demand full transaction audit trails, user identity correlation, enriched financial/transaction signal detection, and a blocklist pipeline that is source-attributed, deduplicated, cached, and DB-synchronized. All work must be designed for sub-millisecond hot-path overhead.

For threat-centric review and control-gap tracking, use the companion [Threat Model (Initial Draft)](./threat-model.md) as the security baseline for this roadmap.

**Guiding principles:**

- Zero blocking I/O on the request hot path — all writes are fire-and-forget via the existing `EventSender` channel or new side-car queues.
- Data captured at the proxy is the ground truth; the proxy publishes sync-plane work through NATS/outbox and the Oracle worker owns Oracle persistence.
- Bandwidth improvements precede new capture features to ensure headroom.
- Every new table/column is guarded by an idempotent migration following the `Vxxx__*.sql` convention already in `sql/`.

### Sync-plane architecture

- `sync.scan.request` is the proxy-to-coordinator discovery subject. Messages identify a stream, observed timestamp, dedupe key, and a payload reference.
- `inline://json/...` references carry small JSON payloads directly. `outbox://...` references point to spooled payload files in the shared sync outbox volume.
- `sync.oracle.load` is the coordinator-to-worker batch dispatch subject. The coordinator dedupes in Postgres, advances cursors, and publishes load batches.
- `sync.oracle.result` is the worker-to-coordinator result subject. The coordinator consumes it from `ORACLE_RESULT_STREAM` and updates `sync_batch`, `sync_job`, and `sync_error`.
- `sync-publish` refers to the proxy-side publish path that prepares payload references and emits `sync.scan.request`; it must never call Oracle directly.

## Execution Mode (How We’ll Run This) {#execution-mode}

To make this workmap operational (not just aspirational), execute in these lanes:

| Lane | Owner | Cadence | Definition of Done |
|------|-------|---------|--------------------|
| **Perf lane** (Epic 4 first) | Network/runtime engineer | Daily benchmark run | Throughput and latency targets met with no regression in existing tests. |
| **Data lane** (Epics 1, 2, 3, 5 DB work) | Backend + DBA | Migration review twice weekly | Migration merged, rollback documented, and writer path load-tested. |
| **Control plane lane** (config/admin endpoints/dashboard) | Platform engineer | PR review within 24h | Config documented, admin endpoint covered by tests, dashboard visible in staging. |
| **Compliance lane** (audit/legal hold semantics) | Security/compliance engineer | Weekly signoff | Event semantics, retention, and role privileges reviewed and approved. |

**Change-management guardrails:**

- Every epic PR should include: code, migration (if needed), test delta, and operational notes.
- No PR may add synchronous network/database I/O to request hot paths.
- Any feature flag defaults to **off** unless it is strictly performance-positive.
- Each milestone closes with a short benchmark + incident-readiness note in this file.

---

## Epic 1 — Transaction-Level Audit & User Session Tracking {#epic-1}

**Goal:** Identify individual users behind the proxy, correlate all their TCP sessions into logical "user sessions", and detect transaction-class operations (financial APIs, auth flows, data-submission endpoints).

### 1.1 — User Identity Resolution

**Files:** `src/config.rs`, `src/tunnel/connect.rs`, `src/tunnel/transparent.rs`, `src/state.rs`

| Task | Detail |
|------|--------|
| **1.1.1** Parse `Proxy-Authorization` username into all event payloads | Extract `username` from Basic auth header in `main.rs` service closure and propagate it through `handle()` and `handle_transparent()` via a new `identity: Option<String>` field on `EmitPayload`. |
| **1.1.2** Add `user_id` / `client_cert_cn` to `ConnectionSessionOpenEvent` | Extend `src/db/types.rs` `ConnectionSessionOpenEvent` with `user_id: Option<String>` and add column via `sql/V007__session_user_id.sql`. |
| **1.1.3** Correlate WireGuard peer public key → username | Store a `DashMap<String, String>` (pubkey → username) in `AppState`, populated on WireGuard handshake events. Emit `wg_peer` field on all tunnel events. |
| **1.1.4** Config: `IDENTITY_HEADER` env var | Allow operators to specify a custom header (e.g. `X-Authenticated-User`) injected by an upstream SSO reverse proxy, read in `ProxyConfig::from_env()`. |
| **1.1.5** MFA claim enforcement for privileged/admin access | Require an upstream MFA claim (e.g. `amr`/`acr`) for admin routes and high-risk control-plane actions. Deny when claim is absent and emit a compliance audit event. |

### 1.2 — Logical User Session (multi-tunnel grouping)

**Files:** `src/state.rs`, `src/db/types.rs`, `sql/V008__user_sessions.sql`

| Task | Detail |
|------|--------|
| **1.2.1** New `UserSession` struct in `AppState` | A `DashMap<String, UserSession>` keyed by `user_id`. Each `UserSession` holds: `session_uuid`, `first_seen`, `last_seen`, `tunnel_count`, `bytes_up`, `bytes_down`, `blocked_count`, `transaction_signals`. |
| **1.2.2** `user_sessions` Oracle table | Columns: `session_uuid`, `user_id`, `peer_ip`, `wg_peer_pubkey`, `started_at`, `last_activity_at`, `tunnel_count`, `bytes_up`, `bytes_down`, `blocked_count`, `risk_tier`, `created_at`. |
| **1.2.3** Flush `user_sessions` via `spawn_oracle_flusher` | Extend the existing 60-second Oracle flusher in `dashboard.rs` to upsert `user_sessions` rows alongside `blocked_events`. |
| **1.2.4** `session_id` foreign key on `connection_sessions` | Add `user_session_uuid VARCHAR2(36)` to `connection_sessions` via `sql/V009__conn_sessions_user_fk.sql`. |

### 1.3 — Transaction & Financial Signal Detection

**Files:** `src/tunnel/classify.rs`, `src/tunnel/tls.rs`, `src/state.rs`

| Task | Detail |
|------|--------|
| **1.3.1** Extend `classify()` with financial/transaction categories | Add patterns: `"payment"`, `"banking"`, `"auth-oauth"`, `"api-graphql"`, `"api-rest-post"`. Detect domains: `stripe.com`, `braintree.com`, `paypal.com`, `plaid.com`, `*.bank*`, `*checkout*`, `*payment*`. |
| **1.3.2** HTTP method sniffing for plaintext 80/tcp tunnels | `capture_plaintext_payloads` defaults to `false` and may only be enabled after documented legal/compliance sign-off. When enabled and `orig_dst.port() == 80`, inspect first 16 bytes of `up_buf` for `POST `, `PUT `, `PATCH ` — set `transaction_signal = true` on the session. |
| **1.3.3** `transaction_signals` JSONB column on `connection_sessions` | `sql/V010__transaction_signals.sql` adds `transaction_signals CLOB CHECK (transaction_signals IS JSON)` to `connection_sessions`. Populated with: `{ method, path_prefix, is_financial, category }`. |
| **1.3.4** `TransactionSignal` event type in `DbEvent` enum | New variant `DbEvent::TransactionSignal(TransactionSignalEvent)` in `src/db/types.rs` with dedicated insert path in `src/db/inserts.rs` writing to a `transaction_signals` table. |

---

## Epic 2 — Intelligent Blocklist Infrastructure {#epic-2}

**Goal:** Replace the single-URL blocklist with a multi-source, Redis-cached, Oracle-synchronized pipeline that is source-attributed and enriched with threat intelligence metadata.

### 2.1 — Multi-Source Blocklist Loader

**Files:** `src/blocklist.rs`, `src/config.rs`

| Task | Detail |
|------|--------|
| **2.1.1** `BlocklistSource` config struct | Add `blocklist_sources: Vec<BlocklistSource>` to `Config`. Each source has: `url: String`, `format: BlocklistFormat` (domains/hosts/adblock), `label: String`, `weight: f32`, `enabled: bool`. Load from `BLOCKLIST_SOURCES` env var as JSON array. |
| **2.1.2** Parallel source fetching in `spawn_refresh_task` | Replace single `fetch()` with `futures::future::join_all()` over all enabled sources. Merge results tagged with their source label. Failure of one source does not abort others. |
| **2.1.3** Adblock/hosts format parsers | Support `format: "adblock"` (`||domain^` lines) and `format: "hosts"` (`0.0.0.0 domain`). Extract domain from each format before inserting into the merged set. |
| **2.1.4** Source attribution map | Replace `ArcSwap<HashSet<String>>` with `ArcSwap<BlocklistSnapshot>` where `BlocklistSnapshot = { domains: HashSet<String>, source_map: HashMap<String, SmallVec<[&str;2]>> }`. Store which sources contributed each domain. |
| **2.1.5** Per-source audit records in `blocklist_audit` | Extend `BlocklistAuditEvent` with `source_label: Option<String>`, `format: Option<String>`. Emit one event per source per refresh cycle. |

### 2.2 — Redis/Valkey Cache Layer

**Files:** `src/blocklist.rs`, `src/config.rs`, `Cargo.toml`

| Task | Detail |
|------|--------|
| **2.2.1** Add `redis` crate dependency | `redis = { version = "0.27", features = ["aio", "tokio-comp", "connection-manager"] }`. Gate behind `blocklist-cache` feature flag. |
| **2.2.2** `BlocklistCache` trait | Define `async fn store(snapshot: &BlocklistSnapshot) -> Result<()>` and `async fn load() -> Result<Option<BlocklistSnapshot>>`. Implement for Redis and a no-op `MemoryCache`. |
| **2.2.3** Redis storage format | Serialize `BlocklistSnapshot` as `MessagePack` (add `rmp-serde` dep). Store under key `ssl-proxy:blocklist:current` with TTL of 25 hours. Store metadata under `ssl-proxy:blocklist:meta` (refresh time, source counts, total domains). |
| **2.2.4** Startup hydration from Redis | On `spawn_refresh_task` init, attempt `cache.load()` first. If a fresh snapshot exists (< 23 hours old), use it immediately — do not wait for a remote fetch. Log `blocklist_source = "redis_cache"`. |
| **2.2.5** `REDIS_URL` config env var | Add to `Config::from_env()` with `Option<String>`. When absent, the cache layer is bypassed silently. |
| **2.2.6** Redis health in `/ready` endpoint | When `REDIS_URL` is configured, include a Redis ping in `dashboard::ready()`. Return degraded status (but not 503) if Redis is unreachable — blocklist still functions from RAM. |

### 2.3 — Oracle Blocklist Synchronization

**Files:** `sql/`, `src/db/`, `src/blocklist.rs`

| Task | Detail |
|------|--------|
| **2.3.1** `blocklist_domains` Oracle table | `sql/V011__blocklist_domains.sql`: `domain VARCHAR2(253) PK`, `sources CLOB IS JSON`, `first_added TIMESTAMP`, `last_seen TIMESTAMP`, `hit_count NUMBER`, `removed_at TIMESTAMP`, `category VARCHAR2(64)`. |
| **2.3.2** Bulk upsert on each successful refresh | After merging sources, batch-upsert all domains into `blocklist_domains`. Use `MERGE` on `domain`, updating `last_seen`, `sources`, incrementing nothing (hit counts updated separately). Batch size: 500 rows per statement. |
| **2.3.3** Hit counter increment on block event | In `record_host_block()` in `state.rs`, enqueue a `DbEvent::BlocklistHit { domain }` that the writer batches and applies as `UPDATE blocklist_domains SET hit_count = hit_count + 1`. |
| **2.3.4** Blocklist diff view | `sql/V012__blocklist_diff.sql`: `v_blocklist_changes` view showing domains added or removed in the last 24 hours by comparing `first_added` and `removed_at` against `SYSTIMESTAMP - INTERVAL '1' DAY`. |

### 2.4 — Artifact Integrity & Allowlisting (Gap Closure)

**Files:** `src/main.rs`, `src/config.rs`, `src/dashboard.rs`

| Task | Detail |
|------|--------|
| **2.4.1** Binary/config allowlisting and integrity attestation | Verify signed release artifact metadata at startup and compute periodic config hash checks against an approved allowlist; emit high-severity alert and fail closed for unauthorized drift. |

---

## Epic 3 — Compliance Data Capture & Scraping Audit {#epic-3}

**Goal:** Capture user-attributable traffic metadata sufficient for compliance and legal hold, including cache-worthy response signals and data-scraping behavioral detection.

### 3.1 — Response Metadata Capture

**Files:** `src/proxy.rs`, `src/db/types.rs`, `src/db/inserts.rs`

| Task | Detail |
|------|--------|
| **3.1.1** Capture response `Content-Type`, `Content-Length`, status codes in `proxy.rs` | After `state.client.request()`, extract `content-type`, `content-length`, `x-cache`, `cf-cache-status` response headers. Add to `EmitPayload.extra` JSON and to `ProxyEvent` via new `response_content_type: Option<String>` and `response_content_length: Option<i64>` fields. |
| **3.1.2** `proxy_events` column additions | `sql/V013__proxy_events_response_meta.sql`: add `response_content_type VARCHAR2(128)`, `response_content_length NUMBER`, `response_cache_status VARCHAR2(32)`. |
| **3.1.3** Detect API vs browser traffic | Classify requests by `Accept` header: `application/json` → `api`, `text/html` → `browser`, `*/*` → `mixed`. Add `traffic_class VARCHAR2(16)` to `proxy_events`. |

### 3.2 — Cache/Object Storage Integration (MinIO)

**Files:** `src/config.rs`, new `src/cache.rs`, `Cargo.toml`

| Task | Detail |
|------|--------|
| **3.2.1** Add `opendal` for MinIO | Use `opendal = { version = "0.48", features = ["services-s3"] }`. Gate behind `payload-store` feature. |
| **3.2.2** `PayloadStore` abstraction | `src/cache.rs`: `async fn store_payload(session_id: &str, direction: Direction, data: &[u8]) -> Result<String>` returns object key. Writes to MinIO bucket `ssl-proxy-payloads/YYYY/MM/DD/{session_id}/{direction}`. |
| **3.2.3** Async payload offload after tunnel close | When `capture_plaintext_payloads` is true and `up_buf` / `down_buf` are non-empty, `tokio::spawn` a task to upload to MinIO. Store the returned object key in `payload_audit.payload_object_key`. |
| **3.2.4** `payload_object_key` column | `sql/V014__payload_object_key.sql`: `ALTER TABLE payload_audit ADD (payload_object_key VARCHAR2(512))`. Remove `payload_bytes RAW(8192)` from hot-path writes — only store the object key in Oracle; raw bytes live in MinIO. |
| **3.2.5** `MINIO_ENDPOINT`, `MINIO_BUCKET`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` env vars | Add to `Config`. `PayloadStore` is disabled (no-op) when `MINIO_ENDPOINT` is absent. |

### 3.3 — Scraping / Data Exfiltration Behavioral Detection

**Files:** `src/state.rs`, `src/tunnel/classify.rs`

| Task | Detail |
|------|--------|
| **3.3.1** Request velocity per user per domain | Track `requests_per_minute: u32` on `HostStats` per `(user_id, domain)` key. Flag as `SCRAPING_SUSPECT` when a single user hits the same domain > 300 req/min by default, with per-domain allowlist/config override. |
| **3.3.2** `scraping_signals` table | `sql/V015__scraping_signals.sql`: columns `user_id`, `target_host`, `requests_in_window`, `window_start`, `peak_hz`, `verdict` (`SUSPECT`/`CONFIRMED`/`CLEARED`), `created_at`. Flushed by Oracle flusher every 60 s. |
| **3.3.3** `bytes_down` anomaly detection | When `bytes_down > 50 MB` in a single session, emit a `high_volume_egress` event with user_id, host, and bytes_down. Write to a new `egress_anomaly_events` table. |
| **3.3.4** Sequential subdomain sweep detection | Detect when a user opens > 10 TCP sessions to different subdomains of the same root domain within 30 seconds — emit `subdomain_sweep` signal. |

---

## Epic 4 — Bandwidth & Performance Hardening {#epic-4}

**Goal:** Maximize tunnel throughput, reduce allocations on the hot path, and ensure the DB write pipeline never creates back-pressure on request handling.

### 4.1 — Zero-Copy Bidirectional Copy

**Files:** `src/tunnel/transparent.rs`, `src/tunnel/connect.rs`

| Task | Detail |
|------|--------|
| **4.1.1** Preserve `copy_bidirectional` transparent fast path | Keep the non-capture path on `copy_bidirectional` as the baseline; only use manual split-and-loop when `capture_payloads == true`. |
| **4.1.2** Increase buffer sizes to 64 KiB | Change all `[0u8; 8192]` read buffers to `[0u8; 65536]` in tunnel copy loops. Reduces syscall frequency by 8x for high-throughput streams. |
| **4.1.3** `SO_SNDBUF` / `SO_RCVBUF` tuning | In `set_keepalive()` helpers (both `connect.rs` and `transparent.rs`), also set `socket2::Socket::set_send_buffer_size(256 * 1024)` and `set_recv_buffer_size(256 * 1024)`. |
| **4.1.4** `TCP_NODELAY` on upstream connections | In `dial_upstream_with_resolver()`, call `stream.set_nodelay(true)?` after successful connect. Eliminates Nagle's algorithm latency for interactive/API traffic. |
| **4.1.5** Connection pool for upstream dials | For HTTP (port 80) connections, maintain a `DashMap<String, Vec<tokio::net::TcpStream>>` idle pool with 30-second idle TTL. Controlled by `UPSTREAM_POOL_SIZE` env var (default 0 = disabled). |

### 4.2 — DNS Resolution Performance

**Files:** `src/tunnel/dial.rs`, `src/state.rs`

| Task | Detail |
|------|--------|
| **4.2.1** DNS cache baseline validation | DNS cache is always-on; keep tests covering successful-resolution cache writes and TTL behavior. |
| **4.2.2** Negative cache for NXDOMAIN | Add `dns_negative_cache: DashMap<String, Instant>` to `AppState`. Skip resolver entirely for domains that returned NXDOMAIN in the last 60 seconds. |
| **4.2.3** Pre-warm DNS cache for blocklist domains on startup | After the first successful blocklist refresh, asynchronously resolve the top-1000 most-hit domains (by `hit_count` from Oracle or seed list) into the DNS cache. |
| **4.2.4** Reduce `DNS_RESOLVE_TIMEOUT_SECS` from 5 to 2 | Most enterprise DNS resolves in < 200 ms. 5-second timeouts can stack up under load. Add `DNS_RESOLVE_TIMEOUT_MS` env var with default 2000 ms. |

### 4.3 — DB Write Pipeline Performance

**Files:** `src/db/writer.rs`, `src/db/mod.rs`

| Task | Detail |
|------|--------|
| **4.3.1** Increase `CHANNEL_CAP` from 4096 to 16384 | The current 4096-event buffer is tight during blocklist refresh bursts. 16384 items at ~512 bytes average = ~8 MB max memory — acceptable. Update `src/db/mod.rs`. |
| **4.3.2** Increase batch drain limit from 64 to 256 | In `writer.rs` inner loop, change `while events.len() < 64` to `256`. Larger batches amortize Oracle round-trip latency. |
| **4.3.3** Typed batch bins pre-allocated at writer startup | Instead of allocating `Vec`s inside `insert_batch()` on every call, maintain pre-allocated `Vec`s in the writer loop that are `clear()`ed after each flush. Eliminates repeated heap allocations. |
| **4.3.4** `ORACLE_BATCH_SIZE` env var | Allow tuning batch size without recompile. Default 256. Cap at 1000 (Oracle bind variable limit considerations). |
| **4.3.5** Back-pressure signal to callers | When `EventSender::try_send()` returns `EnqueueError::Full` more than 100 times per second (tracked with an `AtomicU64` + timestamp), log a `warn!` with queue depth — allows operators to detect undersized Oracle throughput. |

### 4.4 — Connection Limiting & Fairness

**Files:** `src/main.rs`, `src/config.rs`

| Task | Detail |
|------|--------|
| **4.4.1** Per-user connection semaphore | Add `user_semaphores: DashMap<String, Arc<Semaphore>>` to `AppState`. Each authenticated user gets at most `PER_USER_MAX_CONNECTIONS` (default 200) concurrent tunnels. Return `429 Too Many Requests` on exhaustion. |
| **4.4.2** Prioritize WireGuard transparent traffic over explicit proxy | Explicit proxy connections (`EXPLICIT_PROXY_ENABLED=true`) use a separate, lower-capacity semaphore. Transparent proxy (WireGuard) always has the full `max_connections` budget. |

### 4.5 — Network Segmentation & East-West Containment (Gap Closure)

**Files:** `deploy/`, `infra/`, `docs/runbook.md`

| Task | Detail |
|------|--------|
| **4.5.1** Network segmentation policy for control/data plane | Enforce default-deny east-west traffic between ingress, proxy runtime, DB writer, and admin services with explicit allow rules only for required ports/protocols. Add conformance checks in deployment pipeline. |

---

## Epic 5 — Observability & Alerting {#epic-5}

### 5.1 — Structured Metrics

| Task | Detail |
|------|--------|
| **5.1.1** Prometheus metrics endpoint `/metrics` | Add `axum` route on admin port. Export counters: `ssl_proxy_tunnels_total{kind,category}`, `ssl_proxy_blocked_total{category,verdict}`, `ssl_proxy_bytes_up_total`, `ssl_proxy_bytes_down_total`, `ssl_proxy_db_queue_depth`, `ssl_proxy_blocklist_domains_total{source}`. Use `prometheus` crate. |
| **5.1.2** DNS cache hit rate metric | `ssl_proxy_dns_cache_hits_total` and `ssl_proxy_dns_cache_misses_total` counters. |
| **5.1.3** Per-user traffic gauge | `ssl_proxy_user_bytes_up{user_id}` and `ssl_proxy_user_bytes_down{user_id}` gauges, updated on tunnel close. |

### 5.2 — Compliance Audit Log (append-only)

| Task | Detail |
|------|--------|
| **5.2.1** Separate `compliance_events` Oracle table | Immutable records — no UPDATE ever. Columns: `id`, `event_time`, `user_id`, `event_type` (`tunnel_open`, `tunnel_close`, `block`, `transaction_detected`, `scraping_detected`), `host`, `session_uuid`, `bytes_up`, `bytes_down`, `peer_ip`, `wg_peer_pubkey`, `category`, `verdict`, `raw_json CLOB IS JSON`. |
| **5.2.2** Dual-write on all block and transaction events | `events.rs` `emit_serializable()` writes to both `proxy_events` (operational) and `compliance_events` (legal hold) for events where `blocked == true || transaction_signal == true`. |
| **5.2.3** 7-year retention policy in `data_retention_policy` | Insert row: `('COMPLIANCE_EVENTS', 2555, 'EVENT_TIME', 'Legal hold — 7 year minimum')`. |
| **5.2.4** Migration V016 | Apply and document `sql/V016__compliance_events.sql` for compliance event storage and retention policy bootstrap. |

### 5.3 — Dashboard Enhancements

| Task | Detail |
|------|--------|
| **5.3.1** User activity panel in `static/index.html` | New table section: Top 20 users by bytes transferred, blocked count, and transaction signal count. Fetched from new `/users` admin endpoint backed by `UserSession` DashMap. |
| **5.3.2** Blocklist source breakdown widget | Show per-source domain counts and last refresh time. Data from `/blocklist/sources` admin endpoint. |
| **5.3.3** Transaction signal feed | New WebSocket or SSE feed `/events/transactions` emitting only `transaction_detected` events in real time. |

### 5.4 — Security Operations Readiness (Gap Closure)

| Task | Detail |
|------|--------|
| **5.4.1** Patch cadence SLA + overdue alerting | Define severity-based SLAs (e.g., critical 48h, high 14 days) for base images and dependencies; publish weekly overdue report and page on SLA breach. |
| **5.4.2** Recovery runbook validation drills | Execute quarterly backup-restore and failover drills for Oracle/ClickHouse/Redis and proxy config state. Record RTO/RPO evidence and remediation actions. |

---

## Cross-Cutting Concerns {#cross-cutting}

### Security

- All new env vars containing secrets (`REDIS_URL` with auth, `MINIO_SECRET_KEY`) must use the `read_secret(var, file_var)` pattern already established in `config.rs` — never read raw from env in hot path.
- `compliance_events` table must have a separate Oracle role with `INSERT` only — no `UPDATE` or `DELETE`. Document in `sql/roles.sql`.
- MinIO bucket must have versioning enabled and object lock (WORM) configured for legal hold.

### Testing

| Task | Detail |
|------|--------|
| Unit tests for `classify()` new transaction categories | Extend `src/tunnel/classify.rs` tests for `stripe.com`, `paypal.com`, `checkout.*` patterns. |
| Unit tests for new blocklist source parsers | Test adblock format (`||domain^`) and hosts format (`0.0.0.0 domain`) extraction. |
| Integration test for Redis cache round-trip | Add `tests/blocklist_cache.rs` — spin up an in-process mock Redis or use `testcontainers`. |
| Benchmark `copy_bidirectional` vs manual loop | Add `benches/tunnel_throughput.rs` using `criterion`. Target: > 1 Gbps on loopback for the non-capture path. |

### Database Migrations (ordered)

```sql
sql/V007__session_user_id.sql
sql/V008__user_sessions.sql
sql/V009__conn_sessions_user_fk.sql
sql/V010__transaction_signals.sql
sql/V011__blocklist_domains.sql
sql/V012__blocklist_diff.sql
sql/V013__proxy_events_response_meta.sql
sql/V014__payload_object_key.sql
sql/V015__scraping_signals.sql
sql/V016__compliance_events.sql
sql/V017__egress_anomaly_events.sql
```

All migrations follow the existing idempotent PL/SQL `DECLARE / IF v_count = 0 THEN` pattern.

---

## Milestone Schedule {#milestones}

```text
M1 — Performance baseline (Epic 4)          2 weeks
     └─ 4.1 zero-copy, 4.2 DNS cache, 4.3 DB pipeline, 4.4 fairness

M2 — Blocklist intelligence (Epic 2)        2 weeks
     └─ 2.1 multi-source, 2.2 Redis cache, 2.3 Oracle sync

M3 — User identity & sessions (Epic 1.1–1.2)  2 weeks
     └─ identity resolution, logical session grouping

M4 — Transaction & compliance capture (Epics 1.3, 3)  3 weeks
     └─ transaction signals, MinIO payloads, scraping detection

M5 — Observability & compliance audit log (Epic 5)  1 week
     └─ Prometheus metrics, compliance_events table, dashboard

M6 — QA, load testing, security review       1 week
```

**Total estimated: 11 weeks** (team of 2 engineers)

## First Sprint Backlog (Let’s Rock) {#first-sprint}

The first sprint should front-load performance headroom and unblock later compliance capture.

### Sprint 1 priorities (Week 1–2)

- [x] **P0:** Keep the existing non-capture transparent fast path on `copy_bidirectional`; treat it as baseline, not backlog.
- [x] **P0:** Keep DNS positive/negative cache behavior as baseline runtime capability, not new sprint scope.
- [ ] **P0:** Replace placeholder sync payload references with resolvable `inline://json/...` and `outbox://...` references.
- [ ] **P0:** Add NATS auth/TLS configuration to the proxy publisher and surface publisher health through `/ready`.
- [ ] **P1:** Remove stale cutover/backlog drift in docs and inline TODOs so the repo reflects the live architecture.
- [ ] **P1:** Add a coordinator/worker follow-up task for resolving `outbox://...` payload references from shared storage.
- [ ] **P1:** Add a benchmark harness focused on sync-publish and tunnel-regression checks instead of the removed Oracle writer path.

### Sprint 1 acceptance gates

- [ ] `sync.scan.request` emits resolvable payload references with stable prefixes.
- [ ] Large event payloads spool cleanly into the configured outbox without blocking local event broadcast.
- [ ] Publisher auth/TLS misconfiguration degrades readiness visibility without crashing the proxy.
- [ ] Existing test suite passes; new tests cover payload references, publish filtering, and sync config parsing.

---

## Architecture Decisions Record (ADR) {#adr}

### ADR-001 — Redis over Memcached for blocklist cache

Redis is chosen over Memcached because: (a) it supports complex data types allowing the full `BlocklistSnapshot` struct to be stored as a single key, (b) it supports `EXPIRE` with TTL enforcement, (c) it is already a common enterprise deployment alongside Oracle. Memcached would require sharding the domain set across many keys.

### ADR-002 — MinIO over Oracle BLOB for payload storage

Oracle `RAW(8192)` is removed from the hot path in favour of MinIO object storage because: (a) binary payloads up to 4 KiB per direction per session do not belong in a row-oriented database — they inflate index sizes and backup volumes, (b) MinIO supports WORM (object lock) natively for legal hold without Oracle Advanced Security licensing, (c) retrieval is O(1) by object key stored in Oracle.

### ADR-003 — Keep Oracle as the system of record, Redis and MinIO as side stores

Oracle `compliance_events` remains the authoritative legal ledger. Redis and MinIO are performance/storage accelerators that can be rebuilt from Oracle data. This preserves the existing Oracle-centric compliance architecture.

### ADR-004 — Fire-and-forget write path, never block request handling

No new compliance feature may introduce synchronous I/O on the tunnel accept or data-copy hot path. All writes are enqueued to `EventSender` or spawned as background tasks. If the DB writer falls behind, events are dropped with a logged `EnqueueError::Full` — this is acceptable because the proxy's primary SLA is network throughput, not write durability.
