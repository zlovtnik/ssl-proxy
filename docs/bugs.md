# Atheros Sensor — Timestamp Drift Fix & Audit Log Performance Workmap

## Root Cause Analysis

### Why the clock drifts ~2 hours after 5 hours of runtime

There are **three compounding sources** of drift, all interacting:

---

### Bug 1 — `TrafficBucket` uses frame timestamps, not wall clock, to drive window flushes (PRIMARY CAUSE)

**File:** `src/audit/bandwidth.rs` — `flush_if_elapsed()`

```rust
fn flush_if_elapsed(&mut self, observed_at: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
    let Some(window_start) = self.window_start else {
        self.window_start = Some(observed_at);   // <- seeded from FRAME timestamp
        return Vec::new();
    };
    if observed_at < window_start + self.window {
        return Vec::new();
    }
    self.window_start = Some(observed_at);       // <- advanced by FRAME timestamp
    self.drain_window(window_start)
}
```

`window_start` is seeded and advanced by `entry.observed_at`, which is `Utc::now()` at **capture time** (set in `capture.rs`). Under normal load this is fine. But:

- When the Redpanda backlog grows (circuit breaker open, memory backlog filling) the sensor continues capturing packets. Each packet's `observed_at` is captured correctly...
- BUT `process_packet` is async and can be queued behind backlog I/O. Packets already sitting in the `mpsc` channel (capacity 64) have **their own past `observed_at`** baked in at capture time.
- When the backlog clears and processing resumes, a burst of 64 packets with stale timestamps is processed. The window bucket sees these as still-within-window and refuses to flush. Then when it finally does flush, `window_end = window_start + 60s` but `window_start` was 2+ hours ago in wall time.
- The `bandwidth_flush` interval timer in `main.rs` calls `flush_current()` on a separate tokio tick — but `flush_current()` uses `window_start` (a past frame timestamp) to set `window_end`, so the published event's `window_start`/`window_end` fields are historically wrong even though the publish happens now.

**Effect:** `WirelessBandwidthEvent.window_start` and `window_end` lag real time by the accumulated queuing delay.

---

### Bug 2 — `observe_raw()` also seeds `window_start` from a frame timestamp

**File:** `src/audit/bandwidth.rs` — `observe_raw()`

Same issue: unsupported frames also call `observe_raw(observed_at, ...)` where `observed_at` comes from `packet.observed_at` (capture time). Under backlog pressure the same drift accumulates here.

---

### Bug 3 — The channel hopper re-applies the BPF filter on every hop, causing libpcap to restart its internal packet buffer, introducing micro-delays that compound over time

**File:** `src/main.rs` — `spawn_channel_hopper()`

```rust
capture_control.apply_filter(bpf.clone());
```

This is called on every hop (default 1 second). Each `apply_filter` call re-installs the BPF program on the live capture handle. On Linux with ath9k_htc this briefly drains the kernel ring buffer, causing 10–100ms micro-stalls. Over 5 hours: 18,000 hops × ~20ms average stall = ~6 minutes of aggregate stall. Combined with Bug 1, the drift compounds.

---

### Bug 4 — `AuditEntry.observed_at` is serialized from `frame.observed_at` (capture time), not publish time

**File:** `src/parse/frame.rs` — `to_audit_entry()`

```rust
observed_at: ssl_proxy::time::rfc3339_from_utc(frame.observed_at),
```

`frame.observed_at` is `packet.observed_at` which is `Utc::now()` at the moment `capture.rs` received the packet. Under backlog pressure this timestamp is correct (it is when the packet arrived), but when the coordinator ingests it hours later after a reconnect, the `observed_at` is 2+ hours stale relative to ingest time. Downstream dashboards interpret this as "events from 2 hours ago" and the timeline drifts.

---

### Bug 5 — `todo: doc it!` markers on `run_message_loop`, `parse_time`, `hex_value` indicate incomplete implementation review

These are cosmetic but signal areas where logic was added quickly. `parse_time` in `config_subscriber.rs` silently returns `None` on parse failure — if `AUDIT_WINDOW_START` is slightly malformed the window defaults to always-on (no filtering at all), which means the audit layer writes every trace event even outside the intended window. Under load this amplifies I/O.

---

## Task List

### Phase 1 — Fix the timestamp drift (blocking)

- [ ] **T1.1** — Replace frame-timestamp-seeded `window_start` in `TrafficBucket` with wall-clock time.

  `flush_if_elapsed` should accept both the frame timestamp (for ordering/attribution) and `Utc::now()` (for wall-clock window advancement). Specifically:

  - Add a `wall_clock_start: Option<Instant>` field to `TrafficBucket` alongside the existing `window_start: Option<DateTime<Utc>>`.
  - `flush_if_elapsed` checks `wall_clock_start.elapsed() >= window_duration` to decide whether to flush, independent of frame timestamps.
  - `window_start` and `window_end` in the emitted `WirelessBandwidthEvent` continue to reflect the **frame-time** range of the window (correct for attribution), but the flush decision is decoupled to wall clock.
  - Update `observe_raw()` the same way.

- [ ] **T1.2** — Remove the frame-timestamp seed from `window_start = Some(observed_at)` in `flush_if_elapsed`.

  The first call that opens a new window should snapshot `Instant::now()` for the wall clock side and `observed_at` for the attribution side. Keep both.

- [ ] **T1.3** — Audit all callers of `TrafficBucket::observe()` and `observe_raw()` and confirm none pass a synthetic/reused timestamp. Specifically check the backlog reconciliation path in `publish.rs` — if `reconcile_backlog` ever re-feeds entries through the traffic bucket (it currently doesn't, but confirm).

- [ ] **T1.4** — Add a `wall_clock_delta_ms` field to `WirelessBandwidthEvent` (the field already exists on `AuditEntry`/`WifiFrame` but not on bandwidth events). Populate it as `(Utc::now() - observed_at).num_milliseconds()` at flush time. This gives operators a per-window health signal showing how far behind the sensor is.

- [ ] **T1.5** — Fix `WirelessBandwidthEvent.window_end` computation in `drain_window`.

  Currently:
  ```rust
  let window_end = window_start + self.window;
  ```
  When the bucket is flushed by `flush_current()` (the periodic timer path), `window_start` may be far in the past. Change to:
  ```rust
  let window_end = window_start + self.window;
  // but cap at Utc::now() to avoid future timestamps from clock skew
  let window_end = window_end.min(Utc::now());
  ```
  And add a `window_is_partial: bool` field to `WirelessBandwidthEvent` that is `true` when the flush was triggered by timer rather than by an incoming frame crossing the boundary.

---

### Phase 2 — Fix the channel hopper BPF stall (performance)

- [ ] **T2.1** — Remove the `capture_control.apply_filter(bpf.clone())` call from `spawn_channel_hopper` in `main.rs`. The filter does not need to change when only the channel changes. The BPF expression `type mgt or type data` is channel-agnostic — libpcap captures all channels on the monitor interface regardless of which channel the radio is tuned to at any moment.

- [ ] **T2.2** — Only re-apply the BPF filter in the hopper if the filter string itself has actually changed (e.g. after a live push from the Redpanda sensor config subscriber). Add a `current_filter: Arc<RwLock<String>>` shared between the config subscriber and the hopper, and diff before applying.

- [ ] **T2.3** — Add a `channel_hop_count` counter to `CaptureStats` and log it in the heartbeat. This makes the hop rate visible and lets operators detect runaway hopping.

---

### Phase 3 — Audit log reliability and latency improvements

- [ ] **T3.1** — Add a `publish_lag_ms` field to the heartbeat log line in `CaptureStats::log()`. Compute it as the average `(Utc::now() - observed_at)` across the last N packets processed. This gives a runtime-visible lag gauge without needing the metrics endpoint.

- [ ] **T3.2** — Add a backpressure guard in `process_packet`: if `publish_state.memory_backlog_len() > threshold` (e.g. 80% of capacity), skip the MAC device lookup (which adds async I/O per packet) and mark the entry with `identity_source = "mac_lookup_skipped_backpressure"`. This prevents the backlog from growing further while the coordinator is unreachable.

- [ ] **T3.3** — The `mac_lookup_error_cache` in `PipelineState` uses `HashMap<String, Instant>` with manual retain — it is never bounded and grows unboundedly under a sustained lookup failure storm. Replace with an `LruCache<String, Instant>` capped at `MAC_DEVICE_CACHE_SIZE` (4096, same as `mac_device_cache`).

- [ ] **T3.4** — The `probe_accumulator` in `PipelineState` is a `HashMap` with no eviction policy. Under a probe storm (e.g. airport environment) this can accumulate thousands of `(ssid, client_mac)` pairs between flush intervals. Add a `max_probe_accumulator_size` guard: when the map exceeds 8192 entries, drain and flush immediately rather than waiting for the next `inventory_flush` tick.

- [ ] **T3.5** — The `AuditLayer` in `src/audit/layer.rs` holds a `SharedAuditWindow` read lock on every `on_event()` call. Under high frame rate this is a hot contention point. Replace the per-event read lock with an atomic snapshot: add a `is_active: Arc<AtomicBool>` that is updated by a dedicated background task (every 5 seconds) rather than computed per-event.

- [ ] **T3.6** — Document and fix the `parse_time` silent-failure in `config_subscriber.rs`. Currently if `AUDIT_WINDOW_START=9:00` (missing leading zero) is pushed via Redpanda, `parse_time` returns `None` and the window loses its start bound silently. Change to log a `warn!` with the malformed value and keep the previous window state rather than applying a partial update.

---

### Phase 4 — Observability (so you can confirm the fix worked)

- [ ] **T4.1** — Add a `atheros_bandwidth_window_lag_ms` Prometheus gauge to `metrics.rs`. Computed as the median `(publish_time - window_end)` across the last bandwidth flush cycle. This directly measures the drift.

- [ ] **T4.2** — Add `atheros_memory_backlog_len` gauge to the metrics endpoint. Currently the memory backlog size is only visible in warn logs. Exposing it as a metric enables alerting.

- [ ] **T4.3** — Add `atheros_circuit_breaker_state` gauge (0=closed, 1=half-open, 2=open) to the metrics endpoint. This makes the Redpanda connectivity state visible to Prometheus without log scraping.

- [ ] **T4.4** — Add `atheros_channel_hops_total` counter to the metrics endpoint (feeds from T2.3).

- [ ] **T4.5** — In `WirelessBandwidthEvent`, add `published_at: String` (RFC3339 wall clock at publish time). This allows downstream consumers to compute `published_at - window_end` as a drift metric per event, independent of the Prometheus endpoint.

---

### Phase 5 — Code hygiene (low risk, complete the `todo: doc it!` markers)

- [ ] **T5.1** — Document `PacketStream` struct in `capture.rs` (marked `//todo: doc it!`). Add doc comment explaining the mpsc channel capacity of 64 and why that is the effective backpressure limit before the capture thread blocks.

- [ ] **T5.2** — Document `run_message_loop` in `config_subscriber.rs`. Specifically document that TLS is unsupported for config subscribers and why (avoidance of rdkafka dependency), so future maintainers don't try to "fix" it.

- [ ] **T5.3** — Document `parse_time` in `config_subscriber.rs`. Document the two accepted formats (`%H:%M:%S` and `%H:%M`) and what happens on failure.

- [ ] **T5.4** — Document `hex_value` in `config_subscriber.rs`. It is a percent-decode helper; name and doc should make that obvious.

- [ ] **T5.5** — `CaptureError` in `capture.rs` is marked `//todo: doc it!`. Add doc comments to both variants explaining the conditions under which each fires.

---

## Implementation Order

```
T1.1 → T1.2 → T1.3 → T1.5   (drift fix, do these together in one PR)
T1.4 → T4.5                   (attribution fields, can be same PR as drift fix)
T2.1 → T2.2 → T2.3            (hopper fix, low risk, separate PR)
T3.3 → T3.4                   (unbounded map fixes, one PR)
T3.1 → T3.2 → T3.5            (backpressure/observability, one PR)
T3.6                           (config subscriber fix, one PR)
T4.1 → T4.2 → T4.3 → T4.4    (metrics, one PR)
T5.1 → T5.5                   (docs, any time)
```

---

## Quick Verification Steps (after T1.1–T1.5)

1. Run the sensor with `RUST_LOG=debug` for 30 minutes with channel hopping enabled.
2. Watch `window_start` values in the `audit.wireless.bandwidth` Redpanda topic — they should now track wall clock within ±2 seconds of publish time.
3. Check `window_is_partial: true` events — these are timer-flushed windows and should appear once per `DEFAULT_BANDWIDTH_WINDOW_SECS` (60s) even when no frames arrived.
4. Inject a Redpanda outage for 60 seconds, restore, and confirm `window_start` resumes from current wall time rather than the pre-outage timestamp.
5. Monitor `atheros_bandwidth_window_lag_ms` gauge — should stay below 5000ms under normal load.

---

## Embedding backlog and ETL health — diagnosis (2026-09-27)

A console report was raised with three symptoms: "50 loaded / 9551 total",
"Data freshness: unavailable", and "719552 embeddings pending". Measured on
`wiretrap-k3s` / namespace `prod-ssl-proxy` between 23:25Z and 23:53Z.

### Symptom 1 — "50 loaded / 9551" is correct behaviour

`apps/integration-console/atheros-search-ui/src/components/InventoryTable.tsx:21-22`
requests `scope: 'page', page_size: 50`. `internal/search/inventory_table.go:54`
slices page 1 and `internal/search/inventory_table.go:92-101` runs a separate
`COUNT(*)` for the total. 9551 is the device inventory size; 50 is the first
page. **No fix required.**

### Symptom 2 — `freshness: unavailable` is a hard-coded literal

`internal/search/report.go:30` sets `Freshness: "unavailable"` and
`IncompleteCoverage: true` unconditionally, as documented in
`docs/atheros-reporting-data-contract.md`. The UI copy in
`ReportStatus.tsx` renders it verbatim. It is not measuring anything and
therefore cannot become fresh by itself.

### Symptom 3 — the embedding backlog is real and growing

| Signal | Value |
| --- | --- |
| Pending jobs | 721,359 (event 653,507 / behaviour 43,389 / sequence 24,039 / device 424) |
| Claimable now / deferred / attempts exhausted | 721,199 / 160 / 0 |
| Pending jobs with an orphan owner (head-of-line risk) | 0 |
| Oldest pending job | 2026-09-26 16:41:36Z (~31h) |
| Drain rate | 124 jobs/min (worker logs) to 171 jobs/min (30-min `completed_at` mean) |
| Produce rate | ~21.6k–24k documents and embedding jobs per hour, 1:1, sustained 24h |
| Net growth | ~+79 jobs/min |
| Dead work | 63,876 pending jobs (8.9%) target `superseded` documents |
| Largest pending document | 1,393,097 chars `normalized_text` (~600 chunks) |

The claim path is healthy: `internal/worker/lease.go` finds nothing orphaned
and nothing attempt-exhausted, so this is a throughput problem, not a stall.

### Where the time goes

Call chain per job batch (`internal/worker/worker.go` →
`internal/embed/client.go`):

1. **`ChunkText` tokenizes one text at a time over HTTP.** Every text is
   POSTed to the backend's `/tokenize` and `/detokenize` inside a loop
   (`client.go:146-153`, `internal/embed/tokens.go:29-52`). One 480-token
   chunk costs two HTTP round trips before any embedding starts.
2. **Requests are packed up to 4096 tokens each.** `RequestTokenLimit`
   (`tokens.go:19`, applied in `client.go:165-184`) packs 8–10 chunks into a
   single `/v1/embeddings` request. The backend has **4 slots**, so one
   packed request occupies one slot for the whole batch while the other
   three sit idle. Measured on the live backend: 4 separate 400-token
   requests in parallel = **1.66s wall**; one request with 4×400 tokens =
   **7.20s**; one request with 4×480 tokens = **12.33s**.
3. **Request concurrency is hard-coded to 2.** `client.go:191` starts 2
   goroutines regardless of slot count or configuration.
4. **One database transaction per completed job.** `worker.go:185-192`
   calls `storeCompletion` per job (`internal/store/postgres.go`), so a
   batch of 16 pays 16 commits.
5. **A 30s HTTP timeout defers the whole remaining batch.**
   `client.go:81` sets the client timeout; on expiry the worker defers the
   claimed jobs without consuming an attempt (`internal/worker/lease.go`),
   which is why `failed` is structurally 0 while hundreds of thousands of
   jobs age out. Batch latency observed: median 6–9s, p90 19s, **max 429s**,
   plus 35 defers and 88 `readyz` failures in a 17.8-minute window.

Consequence: the consumer sustains ~124–171 jobs/min against a producer
running ~383 jobs/min, so the queue grows without bound. At the measured
drain rate the 31-day-old head of the queue will not clear on its own.

### Producer side

- `services/octopus/.../sql/SearchPreparationSql.scala:443-447` supersedes
  the previous document version but leaves that version's pending
  embedding job behind; 63,876 pending jobs are for superseded documents.
- `documentsMissingEmbeddingJobs` (`SearchPreparationSql.scala:526`) only
  enqueues for `status = 'active'`, so the leak comes from documents
  superseded *after* their job was created.
- `embedding-preparer` injects up to 4 kinds x 250 documents per 10s
  (`cyber-stack/base/java-coordinator/deployment.yaml`,
  `OCTOPUS_PROCESSOR_BATCH_SIZE=250`,
  `OCTOPUS_PROCESSOR_INTERVAL_SECONDS=10`).

### Why the health gauges report nonsense

- `internal/worker/health.go:77-90` counts `octopus_core.ingestion_receipts`
  — the table has **0 rows** — so `ingest_pending` and `ingest_failed` are
  always 0.
- `internal/worker/health.go:64-72` counts
  `octopus_core.wireless_observations` — also **0 rows** — so
  `wireless_events_24h` is always 0.
- `internal/worker/health.go:151-157` reports
  `embedding_dependency: healthy` whenever `failed == 0` and
  `pending > 0`, i.e. healthy at 721k pending.
- `internal/worker/health.go:159-176` never filters
  `octopus_core.work_items.last_seen_at`, so a dead worker still looks
  alive.

### Health gauge sources as implemented

`internal/worker/health.go` now reads the table that actually owns each
gauge (values measured against the live database on 2026-09-28 00:50Z):

| Gauge | Source | Measured |
| --- | --- | --- |
| `wireless_events_24h`, `wireless_last_observed_at` | `atheros_search.search_documents`, `source_kind = 'event'` (two index-bounded subqueries) | 0 events in 24h; newest 2026-09-26 23:15:23Z |
| `ingest_pending`, `ingest_processing`, `ingest_failed` | `octopus_core.sync_events`, status filter | 0 / 0 / 0 |
| `batch_pending`, `batch_processing`, `batch_completed`, `batch_failed` | `octopus_core.sync_batches` | 5,323,943 / 0 / 56,119 / 4,285 |
| `job_stored_*`, `job_effective_*`, `job_orphaned` | `octopus_core.sync_jobs` | 5,323,888 pending; 5,310,000 older than 5 minutes |
| `backlog_pending`, `backlog_failed` | `octopus_core.sync_backlog` | 0 / 0 |
| `embedding_*` | `atheros_search.embedding_jobs` (unchanged) | 738,362 pending |

Notes:

- Events are inserted with `status = 'batched'`
  (`IngestionSql.insertSyncEvent`), so `ingest_pending` and
  `ingest_processing` are structurally 0 and `ingest_failed` is the only
  live transition on that ledger.
- `job_effective_*` mirror `job_stored_*`: the legacy per-job batch rollup
  needs a `sync_batches.job_id` index the schema does not define and would
  be a 10M-row join per refresh. Batch-side state is reported through
  `batch_*`; `job_orphaned` carries the staleness signal.
- Grants: `sql/postgres/octopus_core/grants/least_privilege.sql.tmpl` adds
  column-level `SELECT` on `sync_events`, `sync_batches`, `sync_jobs`, and
  `sync_backlog` for the Atheros Search account. The fixture sits outside
  the manifest `apply_order`, so `manifest_sha256` and
  `POSTGRES_SCHEMA_MANIFEST_SHA256` are unchanged.
- Rollout window: the schema executor Job (sync wave 1) applies the new
  grants after wave-0 pods start, so `/v1/etl/health` can return 500 until
  that hook finishes. Every request retries the refresh, so it self-heals.
- Cost: one refresh measures about 3.5s of database time — the
  `sync_batches` pending count alone is ~2.2s over 5.3M rows — so
  `Snapshot` serves a 30-second cache with a background refresh and
  `cmd/server` warms it at startup. Without the cache the refresh exceeds
  the 3000ms UI budget and reproduces the "Pipeline health unavailable"
  banner.

### Adjacent findings from the gauge repoint

- `octopus_core.sync_jobs` and `octopus_core.sync_batches` hold about 5.3M
  pending rows each with `attempt_count = 0` and `owner_id NULL`; nothing
  has completed since 2026-09-26 16:51Z (jobs) and 17:37Z (batches). The
  dispatch queue is stalled, which the old `work_items` gauges reported as
  0.
- `octopus_core.wireless_frames`, the `search_documents` source table,
  stops at 2026-09-26 23:15:23Z while `octopus_core.sync_events` for
  `wireless.audit` is still live (3,633,205 rows in the last 24h, newest
  2026-09-28 00:51Z): ingest is running and the frames projection is what
  stopped.

### Task list

- [x] **E1.1** — Add `RequestPackTokenLimit` (~512, matching the backend slot
  context) and pack each `/v1/embeddings` request to that budget instead of
  `RequestTokenLimit`; keep `RequestTokenLimit` as the hard safety bound.
- [x] **E1.2** — Replace the hard-coded 2-way request concurrency with
  `ATHSEARCH_EMBEDDING_REQUEST_CONCURRENCY` (default 4, one per backend slot).
- [x] **E1.3** — Fan out `ChunkText` tokenization across the chunk list with
  bounded concurrency while preserving chunk order and offsets.
- [x] **E1.4** — Add a batched completion path (one transaction per batch,
  per-job fallback on failure) in `internal/worker`.
- [x] **E1.5** — Add a per-job chunk/time budget so a single oversized
  document defers instead of monopolizing a worker.
- [x] **E2.1** — Bump `ATHSEARCH_EMBEDDING_BATCH_SIZE` 16 → 32 and set
  `ATHSEARCH_EMBEDDING_REQUEST_CONCURRENCY=4` in
  `cyber-stack/matrix/prod/patches/atheros-search.yaml`, one variable at a
  time.
- [x] **E3.1** — Measured the host `llama-server.service` on `wiretrap` and
  found the real limiter is the Vulkan drop-in's physical batch size, not slot
  or thread count. See "E3.1 llama-server throughput" below.
- [x] **E6.1** — Add `cancel-superseded` to `cmd/embedding-job-repair` so the
  pending jobs that target superseded documents can be reaped instead of
  embedded.
- [x] **E4.1** — Cancel pending embedding jobs when their document is
  superseded in `SearchPreparationSql.persist`.
- [x] **E4.2** — Add a high-water mark so `embedding-preparer` backs off when
  the pending queue exceeds a threshold.
- [x] **E5.1** — Repoint `wireless_events_24h` at
  `atheros_search.search_documents` (already granted).
- [x] **E5.2** — Repoint `ingest_*` at `octopus_core.sync_events`
  (`pending` / `processing` / `failed`), the status-for-status successor of
  the legacy `sync_scan_ingest` these gauges came from; add the column-level
  SELECT grants. `ingestion_evidence` was rejected as the source because it
  has no `processing` state (100% of its 5.45M rows are `processed`), so it
  cannot back all three fields.
- [x] **E5.2b** — Repoint `batch_*`, `job_stored_*`, `job_effective_*`,
  `job_orphaned`, and `backlog_*` from the empty `octopus_core.work_items`
  table at `octopus_core.sync_batches`, `sync_jobs`, and `sync_backlog`.
- [x] **E5.3** — Report a `backlog` state for `embedding_dependency` driven
  by pending age, and freshness-filter `worker_heartbeat`.
- [x] **E5.4** — Update `ReportStatus.tsx`, `api/client.ts`, and the e2e
  fixtures for the repointed gauges while preserving the `/v1/etl/*` field
  contract.

---

## Implementation Order (embedding backlog)

```
E1.1 → E1.2 → E1.3 → E1.4 → E1.5   (client fix, one Go change set)
E2.1                                 (prod config, one variable at a time)
E4.1 → E4.2                         (producer, separate sbt change set)
E3.1                                 (host tuning, gated on approval)
E5.1 → E5.2 → E5.3 → E5.4           (observability, can run in parallel)
```

---

## E3.1 llama-server throughput (measured 2026-09-28)

`llama-server.service` is host-local on `wiretrap` and is not tracked in this
repository. The base unit
(`/etc/systemd/system/llama-server.service`) is overridden by
`/etc/systemd/system/llama-server.service.d/vulkan.conf`, which lowered the
physical batch size when the build was switched to Vulkan:

| | base unit | vulkan drop-in (running) | proposed |
| --- | --- | --- | --- |
| `--ctx-size` | 2048 | 512 | 2048 |
| `--batch-size` | 16384 | 512 | 8192 |
| `--ubatch-size` | 16384 | 512 | 4096 |
| `--parallel` | unset (4) | unset (4) | 4 |

Measured with production serving live traffic on the same iGPU throughout, so
every number is conservative. Each figure is a sustained burst of the packed
request shape the worker sends (4 documents, ~128 tokens each):

| Config | docs/min |
| --- | --- |
| ubatch 512, 4 slots (running) | 197–232 |
| **ubatch 4096, batch 8192, 4 slots** | **389** |
| ubatch 8192, batch 16384, 4 slots | 339 |
| ubatch 4096, batch 8192, 8 slots | 388–426 |

Raising `--ubatch-size` is worth about 1.7x. More slots and more threads are
not: `gpu_busy_percent` on the AMD Renoir iGPU sits at 93–99% throughout, so
the GPU is the ceiling and additional concurrency has nothing to schedule.

### Paths ruled out

- **CPU backend is worse, not better.** The same model on `build/bin` (no
  Vulkan) needs 102 CPU-seconds for 19 documents where the Vulkan build needs
  3.9, and sustains 143 docs/min against the Vulkan build's 232 in a burst.
  A single short request looks 14x faster on CPU, but that is serial small-input
  latency overlapping badly across 4 slots; throughput is what matters and
  Vulkan wins. Do not drop `-ngl 99`.
- **Re-quantization is not viable.** Only `Q8_0` is present in the Hugging Face
  cache. Q5_K_M or Q4_K_M would cut work per document, but the model identity
  is part of the `embedding_jobs` unique key, so a new quantization orphans
  all 1,686,546 completed embeddings. At the achievable rate a re-embed is not
  affordable.
- **More slots/threads.** See the `gpu_busy_percent` reading above.

### Latent risk: `n_ctx_slot` is clamped to 512

`n_ctx_train` for this GGUF is 512, so llama.cpp clamps
`n_ctx_slot = ctx_size / parallel` to 512 and logs
`n_ctx_seq (4096) > n_ctx_train (512)`. `ChunkTokenLimit` is 480, which leaves
room for the template, but the historical journal shows inputs of 532, 552,
569, 597, 642, 688, 737 and 757 tokens rejected with
`input (N tokens) is larger than the max context size (512 tokens)`.

Those rejections are all from 2026-09-11 and 2026-09-12. There are none in
current production, and the running worker log shows only
`context deadline exceeded` and `context canceled` defers, not HTTP 500s. So
this is a boundary to keep in mind if `ChunkTokenLimit` is ever raised, not a
live defect. `RequestPackTokenLimit` was deliberately left at 512.

### Apply

```bash
sudo cp -a /etc/systemd/system/llama-server.service.d/vulkan.conf \
        /etc/systemd/system/llama-server.service.d/vulkan.conf.bak-20260928
# write the proposed column above into the drop-in
sudo systemctl daemon-reload && sudo systemctl restart llama-server.service
```

A restart is safe: the worker pool treats connection failure as
`BackendUnavailableError`, defers the claimed batch without consuming an
attempt, and resumes on the next poll.

---

## Quick Verification Steps (after E1)

1. Re-measure the pack effect against the live backend: one request with
   4×480 tokens should no longer be produced; four 480-token requests should
   complete in parallel in roughly the time of one.
2. Watch `embedding_jobs` growth with:

   ```sql
   SELECT count(*) FROM atheros_search.embedding_jobs WHERE status = 'pending';
   SELECT date_trunc('hour', created_at), count(*)
     FROM atheros_search.embedding_jobs GROUP BY 1 ORDER BY 1 DESC LIMIT 5;
   SELECT date_trunc('hour', completed_at), count(*)
     FROM atheros_search.embedding_jobs
    WHERE completed_at IS NOT NULL GROUP BY 1 ORDER BY 1 DESC LIMIT 5;
   ```

   Success is a sustained drain rate above the ~383/min produce rate and a
   negative pending slope.
3. Confirm `failed` and `defer` counts are explained rather than silently
   zero: `kubectl -n prod-ssl-proxy logs deploy/ssl-proxy-atheros-search | rg 'deferred|failed|readyz'`.
4. `go test ./...` in `apps/integration-console/atheros-search`, then
   `make atheros-search-test`, `make lint`, and
   `python3 scripts/check-docs.py`.