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

- When the NATS backlog grows (circuit breaker open, memory backlog filling) the sensor continues capturing packets. Each packet's `observed_at` is captured correctly...
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

- [ ] **T2.2** — Only re-apply the BPF filter in the hopper if the filter string itself has actually changed (e.g. after a live push from the NATS sensor config subscriber). Add a `current_filter: Arc<RwLock<String>>` shared between the config subscriber and the hopper, and diff before applying.

- [ ] **T2.3** — Add a `channel_hop_count` counter to `CaptureStats` and log it in the heartbeat. This makes the hop rate visible and lets operators detect runaway hopping.

---

### Phase 3 — Audit log reliability and latency improvements

- [ ] **T3.1** — Add a `publish_lag_ms` field to the heartbeat log line in `CaptureStats::log()`. Compute it as the average `(Utc::now() - observed_at)` across the last N packets processed. This gives a runtime-visible lag gauge without needing the metrics endpoint.

- [ ] **T3.2** — Add a backpressure guard in `process_packet`: if `publish_state.memory_backlog_len() > threshold` (e.g. 80% of capacity), skip the MAC device lookup (which adds async I/O per packet) and mark the entry with `identity_source = "mac_lookup_skipped_backpressure"`. This prevents the backlog from growing further while the coordinator is unreachable.

- [ ] **T3.3** — The `mac_lookup_error_cache` in `PipelineState` uses `HashMap<String, Instant>` with manual retain — it is never bounded and grows unboundedly under a sustained lookup failure storm. Replace with an `LruCache<String, Instant>` capped at `MAC_DEVICE_CACHE_SIZE` (4096, same as `mac_device_cache`).

- [ ] **T3.4** — The `probe_accumulator` in `PipelineState` is a `HashMap` with no eviction policy. Under a probe storm (e.g. airport environment) this can accumulate thousands of `(ssid, client_mac)` pairs between flush intervals. Add a `max_probe_accumulator_size` guard: when the map exceeds 8192 entries, drain and flush immediately rather than waiting for the next `inventory_flush` tick.

- [ ] **T3.5** — The `AuditLayer` in `src/audit/layer.rs` holds a `SharedAuditWindow` read lock on every `on_event()` call. Under high frame rate this is a hot contention point. Replace the per-event read lock with an atomic snapshot: add a `is_active: Arc<AtomicBool>` that is updated by a dedicated background task (every 5 seconds) rather than computed per-event.

- [ ] **T3.6** — Document and fix the `parse_time` silent-failure in `config_subscriber.rs`. Currently if `AUDIT_WINDOW_START=9:00` (missing leading zero) is pushed via NATS, `parse_time` returns `None` and the window loses its start bound silently. Change to log a `warn!` with the malformed value and keep the previous window state rather than applying a partial update.

---

### Phase 4 — Observability (so you can confirm the fix worked)

- [ ] **T4.1** — Add a `atheros_bandwidth_window_lag_ms` Prometheus gauge to `metrics.rs`. Computed as the median `(publish_time - window_end)` across the last bandwidth flush cycle. This directly measures the drift.

- [ ] **T4.2** — Add `atheros_memory_backlog_len` gauge to the metrics endpoint. Currently the memory backlog size is only visible in warn logs. Exposing it as a metric enables alerting.

- [ ] **T4.3** — Add `atheros_circuit_breaker_state` gauge (0=closed, 1=half-open, 2=open) to the metrics endpoint. This makes the NATS connectivity state visible to Prometheus without log scraping.

- [ ] **T4.4** — Add `atheros_channel_hops_total` counter to the metrics endpoint (feeds from T2.3).

- [ ] **T4.5** — In `WirelessBandwidthEvent`, add `published_at: String` (RFC3339 wall clock at publish time). This allows downstream consumers to compute `published_at - window_end` as a drift metric per event, independent of the Prometheus endpoint.

---

### Phase 5 — Code hygiene (low risk, complete the `todo: doc it!` markers)

- [ ] **T5.1** — Document `PacketStream` struct in `capture.rs` (marked `//todo: doc it!`). Add doc comment explaining the mpsc channel capacity of 64 and why that is the effective backpressure limit before the capture thread blocks.

- [ ] **T5.2** — Document `run_message_loop` in `config_subscriber.rs`. Specifically document that TLS is unsupported for config subscribers and why (avoidance of async-nats dependency), so future maintainers don't try to "fix" it.

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
2. Watch `window_start` values in the `audit.wireless.bandwidth` NATS subject — they should now track wall clock within ±2 seconds of publish time.
3. Check `window_is_partial: true` events — these are timer-flushed windows and should appear once per `DEFAULT_BANDWIDTH_WINDOW_SECS` (60s) even when no frames arrived.
4. Inject a NATS outage for 60 seconds, restore, and confirm `window_start` resumes from current wall time rather than the pre-outage timestamp.
5. Monitor `atheros_bandwidth_window_lag_ms` gauge — should stay below 5000ms under normal load.