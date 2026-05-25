# Vector Embeddings Worker

This service implements the standalone vector embeddings worker for the ssl-proxy solution.
It is responsible for leasing embedding jobs from Postgres, building identity-stripped text from source rows, sending text to an embedding provider, and storing the resulting vectors and metadata back in Postgres.

## Overview

The vec worker is a Kafka-independent worker that operates entirely through Postgres.
It does not read or write Oracle data directly.
Its main responsibilities are:

- Lease pending embedding jobs from `vec_embedding_jobs`
- Build embedding text and metadata from the source tables:
  - `sync_events` for event embeddings
  - `devices` for device embeddings
  - `vec_behaviour_snapshots` for behaviour window embeddings
- Embed text using an external provider: Ollama or llama.cpp
- Upsert embeddings into `vec_embeddings`
- Mark jobs completed, failed, or pending again when retries or lease expiry occur
- Track worker heartbeats in `vec_worker_state`

## Runtime model

The worker runs as a single process with a polling loop.
It loads configuration from environment variables and connects to Postgres.
The runtime behavior is defined in `src/main.rs` and `src/worker.rs`.

Core behavior:

- On startup it initializes structured JSON logging and reads configuration.
- It connects to the configured PostgreSQL database URL.
- It uses `run_forever()` unless the CLI `--once` flag is specified.
- Each loop iteration calls `run_once()`:
  - mark worker state as `running`
  - lease a batch of jobs
  - process jobs in request-sized chunks
  - mark worker state as `idle`
- If no jobs are leased, it sleeps for `POLL_INTERVAL_SECONDS` before retrying.
- Every 10 iterations it calls `vec_release_expired_leases()` to reclaim stale leases.
- The worker handles graceful shutdown on SIGINT/SIGTERM.

## Configuration

The worker is configured entirely by environment variables.
Required values and defaults are defined in `src/config.rs`.

### Required

- `DATABASE_URL` or `SYNC_DATABASE_URL`
  - PostgreSQL connection string for the shared sync database.
- `VECTOR_EMBEDDING_MODEL`
  - Required only when `VECTOR_EMBEDDINGS_ENABLED=true`.
- `VECTOR_EMBEDDING_DIMENSIONS`
  - Required only when `VECTOR_EMBEDDINGS_ENABLED=true`.

### Optional / defaults

- `VECTOR_EMBEDDINGS_ENABLED`
  - Default: `false`
  - When disabled, the worker still runs but default provider/model values are used only for dry-run style behavior.
- `VECTOR_EMBEDDING_PROVIDER`
  - Accepted: `ollama`, `llamacpp`
  - Default: `ollama`
- `VECTOR_EMBEDDING_URL`
  - Default: `http://127.0.0.1:11434` for Ollama
  - Default: `http://127.0.0.1:8080` for llama.cpp
- `VECTOR_EMBEDDING_BATCH_SIZE`
  - Default: `64`
  - Number of jobs leased per run.
- `VECTOR_EMBEDDING_REQUEST_BATCH_SIZE`
  - Default: `min(batch_size, VECTOR_EMBEDDING_REQUEST_BATCH_MAX)`
  - Number of texts sent to the provider in one `embed_many` HTTP call.
- `VECTOR_EMBEDDING_REQUEST_BATCH_MAX`
  - Default: `128`
  - Upper bound for the default request batch size when `VECTOR_EMBEDDING_REQUEST_BATCH_SIZE` is unset.
- `VECTOR_EMBEDDING_LEASE_SECONDS`
  - Default: `1800`
  - Lease duration for jobs in seconds.
- `VECTOR_EMBEDDING_WORKER_NAME`
  - Default: hostname or `unknown-worker`
  - Used as `locked_by` in `vec_embedding_jobs` and as the worker identity in `vec_worker_state`.
- `POLL_INTERVAL_SECONDS`
  - Default: `5`
  - Sleep interval when no jobs are leased or after an error.
- `VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES`
  - Default: `8`
  - Reserved for future per-job prepare parallelism; source fetches use batched `ANY()` queries per chunk.
- `VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES`
  - Default: `16`
  - Limits concurrent per-job completion transactions when bulk complete falls back.
- `VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS`
  - Default: `4`
  - Maximum in-flight embedding HTTP requests across chunks (increase when the provider can serve parallel batches).
- `DATABASE_POOL_MAX_CONNECTIONS`
  - Default: `max(prepares, completes, embed_requests) + 2`, floor `10`
  - Postgres connection pool size for the worker.
- `LOG_FORMAT`
  - Default: JSON structured logs
  - Set to `text`, `pretty`, or `human` for human-readable local output
- `RUST_LOG`
  - Standard tracing filter (default: `vec_worker=info,sqlx=warn`)

### CLI flags

- `--once`
  - Run a single pass and exit.
- `--dry-run`
  - Load config, log it, and exit without entering the worker loop.

## Tables used by vec worker

The vec worker reads and writes the following Postgres tables.

### `vec_embedding_jobs`

This is the work queue for vector embeddings.

Role:

- stores embedding jobs created by upstream sync/coordinator logic
- tracks status, lease state, retry counts, and job metadata

Relevant columns:

- `job_id` — primary key
- `source_table`, `source_key`
  - identify the row to embed
  - `source_table` is one of: `sync_events`, `devices`, `vec_behaviour_snapshots`
  - `source_key` is the primary key value of that row as text
- `embedding_model` — model name used for this job
- `embedding_kind` — one of `event`, `device`, `behaviour_window`
- `status` — one of `pending`, `leased`, `completed`, `failed`
- `priority` — ordering for lease selection
- `attempts`, `max_attempts`
- `lease_token`, `leased_at`, `locked_by`
- `due_at` — earliest time the job may be leased
- `content_sha256` — SHA-256 of the generated embedding text
- `last_error` — latest failure reason
- `completed_at`, `created_at`, `updated_at`

Constraints and indexes:

- `vec_embedding_jobs_source_unique` unique on `(source_table, source_key, embedding_model, embedding_kind)`
- `vec_embedding_jobs_kind_chk` ensures `embedding_kind` is valid
- `vec_embedding_jobs_status_chk` ensures `status` is valid
- `vec_embedding_jobs_attempts_chk` ensures attempt counts are sane
- `vec_embedding_jobs_pending_idx` indexes pending/failed jobs by `(priority, due_at, job_id)`
- `vec_embedding_jobs_lease_idx` indexes leased rows by `leased_at`

Usage by vec worker:

- `lease_jobs()` calls the DB function `vec_lease_embedding_jobs()` to atomically mark jobs as `leased`
- `complete_job()` updates status to `completed` and clears lease fields
- `fail_job()` marks a job `failed` if retries are exhausted, or resets it to `pending` with a backoff delay

### `vec_embeddings`

This table stores the resulting vectors and metadata for completed embedding jobs.

Role:

- primary storage for embeddings and the text used to generate them
- supports dedupe and similarity queries through indexes

Relevant columns:

- `embedding_id` — primary key
- `source_table`, `source_key` — origin row identity
- `source_observed_at`, `source_stream_name`, `source_sensor_id`, `source_location_id`, `source_mac`
- `embedding_model`, `embedding_kind`
- `embedding_dimensions` — required positive integer
- `content_sha256` — text hash used to detect changed content
- `content_text` — the exact text sent to the embedding provider
- `embedding` — pgvector column storing the vector
- `metadata` — JSONB with optional source metadata fields
- `embedded_at`, `created_at`, `updated_at`

Constraints and indexes:

- `vec_embeddings_source_unique` unique on `(source_table, source_key, embedding_model, embedding_kind)`
- `vec_embeddings_kind_chk` validates allowed kinds
- `vec_embeddings_dimensions_chk` validates positive dimensions
- indexes on `(source_table, source_key)` and `(embedding_kind, embedding_model, embedded_at desc)`
- conditional index on `lower(source_mac), source_observed_at desc` when `source_mac` is not null
- pgvector HNSW indexes for `embedding_kind` / `embedding_model` / `embedding_dimensions = 768` for event/device/behaviour_window

Usage by vec worker:

- `upsert_embedding()` inserts or updates rows using `ON CONFLICT` on the unique source key tuple
- the worker stores the vector, raw embedding text, and metadata with `embedded_at = now()`

### `vec_worker_state`

This table tracks the live heartbeat and status of each vec worker instance.

Role:

- observable worker health and progress tracking
- helps identify stale or dead workers

Relevant columns:

- `worker_name` — primary key, set from `VECTOR_EMBEDDING_WORKER_NAME`
- `status` — typically `running` or `idle`
- `last_cursor` — optional cursor state if the worker tracks progress
- `last_run_started_at`, `last_run_finished_at`
- `rows_processed` — accumulated count of completed jobs
- `last_error`
- `updated_at`

Usage by vec worker:

- `mark_worker_state()` is called before and after each run
- the insert uses `ON CONFLICT (worker_name) DO UPDATE`
- when a positive `rows_processed` value is reported, it is added to the existing counter
- `last_cursor` and run timestamps are merged with `COALESCE` so older values are preserved when absent

### `sync_events`

This is the source audit table for event embeddings.

Role:

- stores raw audited wireless event payloads and parsed fields
- acts as the source row for `event` embeddings

Relevant columns used by vec worker:

- `dedupe_key` — primary key and event identifier used as `source_key`
- `stream_name`
- `observed_at`
- `payload` — JSONB with event details
- semantic event fields such as `ssid`, `frame_type`, `transport_protocol`, `dns_query_name`, `mdns_name`, `dhcp_hostname`, `wps_device_name`, `wps_manufacturer`, `wps_model_name`, `device_fingerprint`, `handshake_captured`, `protected`, `channel_number`, `signal_dbm`, `retry`, `more_data`, `power_save`, `security_flags`
- fallback scalar fields such as `source_mac`, `sensor_id`, `location_id`

Usage by vec worker:

- `build_event()` loads the source row by `dedupe_key`
- semantic-only fields are marshalled into text lines in a deterministic order
- source metadata fields are included in `EmbeddingInput.metadata`
- text is identity-stripped, only including allowed semantic fields and non-sensitive metadata

### `devices`

This is the identity table for devices.

Role:

- stores known device identity attributes
- acts as the source row for `device` embeddings

Relevant columns used by vec worker:

- `mac_id` — primary key and `source_key`
- `display_name`, `username`, `hostname`, `os_hint`, `mac_hint`
- `first_seen`, `last_seen`

Usage by vec worker:

- `build_device()` selects the row by `mac_id`
- available fields are serialized into text lines
- `source_mac` is populated from `mac_id`
- `last_seen` becomes `source_observed_at`

### `vec_behaviour_snapshots`

This table contains behaviour window summaries and optional prebuilt embedding text.

Role:

- stores aggregated device behaviour windows for `behaviour_window` embeddings
- can provide a precomputed `embedding_text` or fall back to summary fields

Relevant columns used by vec worker:

- `snapshot_id` — primary key and `source_key`
- `embedding_text` — preferred identity-stripped text
- `text_summary` — fallback text when no embedding text exists
- `window_start`, `sensor_id`, `location_id`, `source_mac`
- `event_count`, `protocol_mix`, `frame_type_distribution`, `signal_min_dbm`, `signal_max_dbm`, `signal_avg_dbm`, `retry_count`, `protected_count`, `unprotected_count`, `unique_bssid_count`, `mac_rotation_indicators`

Usage by vec worker:

- `build_behaviour_window()` selects the snapshot row by `snapshot_id`
- if `embedding_text` is present, it is used directly
- otherwise `text_summary` is used if available
- as a last resort, a deterministic fallback text is built from individual snapshot fields

## Database functions used by vec worker

### `vec_lease_embedding_jobs(p_limit, p_worker_name, p_lease)`

- returns a set of rows from `vec_embedding_jobs`
- selects jobs where:
  - `status` is `pending` or `failed`, or
  - `status = leased` and `leased_at` is older than the lease interval
  - `attempts < max_attempts`
  - `due_at <= now()`
- locks rows using `FOR UPDATE SKIP LOCKED`
- updates selected rows:
  - `status = 'leased'`
  - increments `attempts`
  - generates a `lease_token`
  - sets `leased_at = now()`
  - sets `locked_by = p_worker_name`
  - clears `last_error`
- returns the updated job rows

The vec worker calls this function through `db::lease_jobs()`.

### `vec_release_expired_leases(p_lease_interval)`

- updates any `vec_embedding_jobs` with `status = 'leased'` whose `leased_at` is older than the lease interval
- resets those rows to `status = 'pending'`
- clears `lease_token`, `leased_at`, and `locked_by`
- sets `due_at = now()` and `last_error = 'lease expired'`

The worker invokes this every 10 iterations to reclaim stuck leases.

### `vec_complete_embedding_batch(p_payload jsonb)`

- Accepts a JSON array of embedding completion rows (job id, lease token, source fields, vector literal, metadata).
- Upserts all rows into `vec_embeddings` in one statement (`ON CONFLICT DO UPDATE`).
- Marks matching jobs `completed` when `lease_token` matches.
- Returns the number of jobs updated.
- Called by `db::complete_embedding_batch()` after each embedded chunk.

## Embedding processing flow

The worker pipeline is implemented in `src/worker.rs`.

1. `run_once()` marks worker state as `running`.
2. `lease_jobs()` obtains a batch of jobs from `vec_embedding_jobs`.
3. If no jobs are leased, the worker marks itself `idle` and returns.
4. `process_jobs()` splits leased jobs into request-sized chunks and pipelines stages across chunks:
   - prepare chunk *k+1* while embedding chunk *k*
   - complete chunk *k-1* while preparing/embedding later chunks
5. For each chunk:
   - `prepare_chunk()` calls `text_builder::build_text_batch()` (batched `WHERE key = ANY(...)` per embedding kind), then computes `content_sha256` per job
   - `embed_chunk()` calls `embed_many()` once for the chunk (limited by `VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS`)
   - `complete_chunk()` calls `vec_complete_embedding_batch()` for all successful vectors in one DB round-trip; falls back to concurrent per-job transactions on partial failure
   - logs `prepare_ms`, `embed_ms`, `complete_ms`, `jobs_ok`, and `jobs_failed` at INFO
6. After each run, `mark_worker_state()` records `idle`, `rows_processed`, and `last_run_finished_at`.

### Job failure handling

- Jobs may fail during preparation, embedding, or completion.
- `fail_job()` marks a job `failed` when `attempts >= max_attempts`.
- If retries remain, the job is returned to `pending` with `due_at = now() + backoff`.
- Backoff seconds are computed as `min(300, max(10, attempts * 10))`, matching the Ruby reference.

## Text builder reference

The worker supports three embedding kinds.

### `event`

- Source: `sync_events` row where `dedupe_key = source_key`
- Builds text from semantic event fields (frame type, app protocol, transport protocol, security flags, DNS/mDNS names, WPS fields, device fingerprint, handshake captured, protected state, signal, retry, power save, etc.)
- Includes `kind: event` as the first line
- Populates `EmbeddingInput` metadata from `observed_at`, `stream_name`, `sensor_id`, `location_id`, and `source_mac`

### `device`

- Source: `devices` row where `mac_id = source_key`
- Builds text from identity fields such as `display_name`, `username`, `hostname`, `os_hint`, `mac_hint`, and time range fields (`wg_pubkey` is intentionally excluded — no semantic value, leaks infra topology)
- Includes `kind: device` as the first line
- Populates `source_mac` from `mac_id`
- Uses `last_seen` as `source_observed_at`

### `behaviour_window`

- Source: `vec_behaviour_snapshots` row where `snapshot_id::text = source_key`
- Preferred text is `embedding_text`
- Falls back to `text_summary`
- If neither exists, constructs deterministic fallback text from snapshot fields
- First line is `kind: behaviour_window`
- Populates metadata from `window_start`, `sensor_id`, `location_id`, and `source_mac`

## Compatibility

- **Ollama**: requires Ollama >= 0.1.26 for batched `POST /api/embed` (multi-input). Older versions used `/api/embeddings` (singular, single-input only).
- **llama.cpp**: server with embedding support; `POST /v1/embeddings` (OpenAI-compatible). Set `VECTOR_EMBEDDING_PROVIDER=llamacpp`.

## Model expectations

The vec worker expects the embedding provider to behave as follows:

- receive a list of plain text strings
- return a vector for each string
- each vector must be a numeric array of length exactly `VECTOR_EMBEDDING_DIMENSIONS`
- returned dimensions are validated by `validate_dimensions()`
- supported providers are:
  - `ollama` via `POST /api/embed`
  - `llamacpp` via `POST /v1/embeddings`

If a model returns a vector with the wrong length, the job is failed and retried according to the same job retry policy.

### Supported embedding kinds

- `event`
- `device`
- `behaviour_window`

### Embedding vector storage semantics

- Embeddings are stored in `vec_embeddings.embedding` as a `vector` type.
- The worker formats the vector as a pgvector literal `[f1,f2,...]`.
- `ON CONFLICT` upsert semantics ensure repeated jobs for the same source row/model/kind update the existing embedding row.

## Performance and horizontal scaling

Throughput comes from **larger lease batches**, **larger embed HTTP batches**, **bulk Postgres completion**, and **multiple worker replicas**.

### Single-process tuning (starting point)

```bash
VECTOR_EMBEDDING_BATCH_SIZE=64
VECTOR_EMBEDDING_REQUEST_BATCH_SIZE=32
VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS=2
DATABASE_POOL_MAX_CONNECTIONS=16
```

Watch structured logs for `batch timing` (`prepare_ms`, `embed_ms`, `complete_ms`) and raise or lower batch sizes based on which stage dominates.

### Multiple replicas

Run **2–4** `vec-worker` containers (or processes), each with a **unique** `VECTOR_EMBEDDING_WORKER_NAME`. Postgres `vec_lease_embedding_jobs` uses `FOR UPDATE SKIP LOCKED`, so replicas coordinate without double-processing.

Tune the embedding provider separately (for example Ollama `OLLAMA_NUM_PARALLEL`, llama.cpp server thread/batch settings). The worker batches HTTP requests; the provider must keep up.

If replicas contend on leases but the queue stays deep, increase `VECTOR_EMBEDDING_BATCH_SIZE` slightly or add another replica rather than raising poll frequency.

## Operational notes

- This worker does not own topic or Kafka logic; it works only with Postgres-based jobs and tables.
- `VECTOR_EMBEDDING_LEASE_SECONDS` should match lease cleanup expectations; the schema default and release function use 30 minutes.
- `POLL_INTERVAL_SECONDS` controls idle polling frequency and should be balanced between latency and database load.
- `vec_worker_state` is the only worker-specific status table; it is safe to monitor for stale or unhealthy worker instances.

## External dependencies: PSQL cron jobs

The vec-worker is a **consumer** of embedding jobs - it never creates them, and it never builds the behaviour snapshots it reads. Both are produced by Postgres cron jobs defined in `vec_install_cron_jobs()` at `sql/postgres.sql` (lines 2004-2045). `pg_cron` must be installed and the `cron` schema available.

Without these cron jobs the worker would run forever, lease nothing, and produce zero output.

### Cron job reference

| # | Name | Schedule | Function | Produces | Consumed by worker |
|---|------|----------|----------|----------|--------------------|
| 1 | `vec-enqueue-embedding-jobs` | `*/2 * * * *` (every 2 min) | `vec_enqueue_embedding_jobs()` | Scans `sync_events` (`wireless.audit`), `devices`, `vec_behaviour_snapshots` -> inserts/updates `pending` rows into `vec_embedding_jobs` | Yes - this is the sole source of work items |
| 2 | `vec-build-behaviour-snapshots` | `*/5 * * * *` (every 5 min) | `vec_build_behaviour_snapshots()` | Aggregates recent wireless events into 15-min behaviour windows in `vec_behaviour_snapshots` | Yes - the worker reads `embedding_text` / `text_summary` from this table |
| 3 | `vec-materialize-similarity-pairs` | `*/5 * * * *` (every 5 min) | `vec_materialize_similarity_pairs()` | HNSW ANN search -> `vec_similarity_pairs`, marks dedupe suspects on `wireless_frames`, creates shadow IT alerts | No - consumes worker output |
| 4 | `vec-release-expired-leases` | `* * * * *` (every 1 min) | `vec_release_expired_leases()` | Reclaims `leased` jobs whose lease interval has expired back to `pending` | Overlapping - the worker also does this internally every 10 iterations |
| 5 | `vec-reap-stale-workers` | `*/5 * * * *` (every 5 min) | `vec_reap_stale_workers()` | Marks dead worker heartbeats in `vec_worker_state` as `stale` | No - observability only |

Jobs #1, #2, and #4 are directly required for the worker to function. If any of them stop running, the embedding pipeline stalls:

- **#1 missing** -> `vec_embedding_jobs` stays empty -> worker leases nothing
- **#2 missing** -> behaviour window jobs fail because `vec_behaviour_snapshots` rows are never created
- **#4 missing** -> jobs orphaned by a crashed worker are never reclaimed, causing permanent queue stalls

### Re-embedding on text builder changes

Migration `V021__vec_reembed_jobs_function.sql` adds `vec_reembed_changed_jobs(p_limit)` - a helper function that re-queues embedding jobs for rows whose stored `content_sha256` no longer matches the SHA-256 of `content_text`. It is **not** scheduled by cron; it is an on-demand function to be called manually (or via a one-shot job) after text builder changes are deployed:

```sql
SELECT vec_reembed_changed_jobs(p_limit => 1000);
```

### Where the cron definitions live

```text
sql/postgres.sql  ->  vec_install_cron_jobs()  (end of file)
```

The individual functions (`vec_enqueue_embedding_jobs`, `vec_build_behaviour_snapshots`, `vec_materialize_similarity_pairs`, `vec_release_expired_leases`, `vec_reap_stale_workers`) are defined in the same file, lines 1175–2002.

## Relevant source files

- `services/vec-worker/src/main.rs` — startup, CLI, logging, and process entry point
- `services/vec-worker/src/config.rs` — environment variable parsing and validation
- `services/vec-worker/src/worker.rs` — leasing loop, batch processing, job lifecycle, shutdown
- `services/vec-worker/src/db.rs` — Postgres access, job update, embedding upsert, worker heartbeat
- `services/vec-worker/src/text_builder.rs` — source row reads and embedding text construction

- `sql/postgres.sql` — Postgres table definitions and helper functions used by the worker

# vec-worker: Performance & Correctness Recovery
## From 55 jobs/min → target 2,000+ jobs/min

---

## Situation assessment from your queue metrics

| Signal | Value | Diagnosis |
|--------|-------|-----------|
| `behaviour_window` jobs | 664 failed, 0 completed | **100% failure — broken, not slow** |
| `event` jobs/min (15m avg) | 55.87 | Severely throttled vs architecture capacity |
| `event` jobs/min (1h avg) | 7,215 / 60 = 120/min | Inconsistent — suggests intermittent stalls |
| Currently leased | 0 | Worker idle between polls at time of snapshot |
| ETA at current rate | 2026-05-29 | 8 days for 621K jobs — unacceptable |
| Oldest remaining | 2026-05-16 | Jobs sitting for 5 days, not being processed |

The 1h rate (120/min) vs 15m rate (55/min) tells you the worker is getting worse
over time during this session, not better. This is either a memory pressure issue,
a pool exhaustion issue, or the alert sweep introduced in the last change is blocking
the embedding loop.

---

## Fix 1 — Behaviour window 100% failure (fix today, before anything else)

664 jobs, 0 completions, 100% failure. This is a schema or query mismatch, not a
performance issue. The most likely causes in order of probability:

### 1a. The `vec_build_behaviour_snapshots` cron job is not running

If the cron job (runs every 5 min per README) stopped, `vec_behaviour_snapshots`
rows exist but have no `embedding_text` and no `text_summary`, and the fallback
builder constructs empty or near-empty text. The worker may be failing on empty
content or the SHA mismatch check.

**Verify:**
```sql
-- Check if snapshots exist and have content
SELECT
  COUNT(*) AS total,
  COUNT(embedding_text) AS has_embedding_text,
  COUNT(text_summary) AS has_text_summary,
  MAX(created_at) AS latest_created
FROM vec_behaviour_snapshots;

-- Check the actual last_error on failed jobs
SELECT last_error, COUNT(*) FROM vec_embedding_jobs
WHERE embedding_kind = 'behaviour_window'
  AND status = 'failed'
GROUP BY last_error
ORDER BY COUNT(*) DESC
LIMIT 10;
```

### 1b. The `snapshot_id::text` cast is producing wrong keys

The query uses `WHERE snapshot_id::text = $1` but the job's `source_key` may have
been stored with a different text representation (e.g., UUID with/without braces,
or a bigint that doesn't match). One wrong cast causes 100% failure.

**Verify:**
```sql
-- Cross-check: do job source_keys match snapshot_id::text?
SELECT j.source_key, s.snapshot_id::text
FROM vec_embedding_jobs j
LEFT JOIN vec_behaviour_snapshots s
  ON s.snapshot_id::text = j.source_key
WHERE j.embedding_kind = 'behaviour_window'
  AND j.status = 'failed'
LIMIT 5;
```

### 1c. The `vec_build_behaviour_snapshots()` function changed its output schema

If the snapshot table schema changed (e.g., `window_end` column added, or
`mac_rotation_indicators` type changed), the `BehaviourWindowRow` sqlx struct
will fail to deserialize and every job fails immediately on `text_build error`.

**Fix:** Check the `last_error` from the query above. If it says
`text_build error: behaviour_window query failed`, the struct is mismatched.
Add `window_end` to the struct or check for column type changes.

### Action

```sql
-- Re-queue all failed behaviour_window jobs after fixing the root cause
UPDATE vec_embedding_jobs
SET status = 'pending',
    attempts = 0,
    last_error = NULL,
    due_at = NOW(),
    updated_at = NOW()
WHERE embedding_kind = 'behaviour_window'
  AND status = 'failed';
```

---

## Fix 2 — The alert sweep is killing throughput

Looking at `worker.rs`, the alert sweep runs inside the main worker loop every
10 iterations:

```rust
if iteration % 10 == 0 {
    // ... release_expired_leases
    let alert_cfg = AlertConfig::default();
    if let Err(e) = alerts::run_alert_sweep(&pool, &alert_cfg).await {
        warn!(error = %e, "alert sweep failed");
    }
}
```

And `check_near_duplicates` in `alerts.rs` queries `v_device_repetition_score`
which is a **view** (not a materialized view). With 2.7M+ rows in `vec_embeddings`
and `vec_similarity_results`, this view scan can take 10-60 seconds. It runs
synchronously in the main loop, blocking lease → embed → complete for its entire
duration.

**The math:** If the sweep takes 30s and runs every 10 iterations at ~5s poll
interval, it fires every ~50s and blocks for 30s of that — 60% of worker time
is spent in the alert sweep.

### Fix 2a — Move alert sweep to a background task

```rust
// In run_forever(), replace the inline alert sweep with a spawned task:
if iteration % 10 == 0 {
    match db::release_expired_leases(&pool).await {
        Ok(released) if released > 0 => info!(released, "expired leases released"),
        Err(e) => warn!(error = %e, "release_expired_leases failed"),
        _ => {}
    }
    // Spawn alert sweep as background task — never blocks the embedding loop
    let alert_pool = pool.clone();
    tokio::spawn(async move {
        let alert_cfg = AlertConfig::default();
        if let Err(e) = alerts::run_alert_sweep(&alert_pool, &alert_cfg).await {
            warn!(error = %e, "alert sweep failed (background)");
        }
    });
}
```

### Fix 2b — Materialize the view

If `v_device_repetition_score` is a plain view, convert it to a materialized view
and refresh it from the background task instead of querying the live view:

```sql
-- Convert to materialized view (run once)
CREATE MATERIALIZED VIEW v_device_repetition_score AS
SELECT
  source_mac,
  COUNT(*) AS near_duplicate_pairs,
  MIN(distance) AS min_distance,
  AVG(distance) AS avg_distance,
  COUNT(DISTINCT embedding_id_a) AS unique_events_implicated
FROM vec_similarity_results
WHERE relation_type = 'event_event'
  AND distance < 0.05
  AND created_at >= NOW() - INTERVAL '24 hours'
GROUP BY source_mac;

CREATE UNIQUE INDEX ON v_device_repetition_score(source_mac);
```

Then in the background sweep task:
```sql
REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score;
```

The `CONCURRENTLY` flag allows reads during the refresh (requires the unique index).

---

## Fix 3 — Batch size and concurrency are misconfigured for current workload

The current default settings from `config.rs`:

```
batch_size: 64
request_batch_size: min(64, 64) = 64
max_concurrent_embed_requests: 1
max_concurrent_prepares: 8  (unused — batch query does all prepares in one query)
max_concurrent_completes: 8
```

With `max_concurrent_embed_requests: 1` and a single `embed_many` HTTP call per
chunk, the pipeline is:

```
prepare_chunk (batch DB query) → embed_many (HTTP, SEQUENTIAL) → complete_chunk
```

The HTTP call to Ollama/llama.cpp is the bottleneck. With 64 texts per call and
~500ms per call (rough estimate for nomic-embed-text), you get:
`64 texts / 0.5s = 128 texts/s = ~128 jobs/min`

Your actual 55/min is even below this, confirming the alert sweep overhead.

### Recommended env config for a single worker

```bash
# Tune for Ollama with nomic-embed-text-v2-moe on a GPU
VECTOR_EMBEDDING_BATCH_SIZE=256
VECTOR_EMBEDDING_REQUEST_BATCH_SIZE=64     # How many texts per HTTP call to Ollama
VECTOR_EMBEDDING_REQUEST_BATCH_MAX=128
VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS=4  # 4 parallel HTTP calls
VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES=16
DATABASE_POOL_MAX_CONNECTIONS=24
POLL_INTERVAL_SECONDS=1
```

With `max_concurrent_embed_requests=4`, the pipeline runs 4 embed HTTP calls
simultaneously. At 64 texts each × 4 concurrent = 256 texts in flight.
At 500ms/call: `256 / 0.5 = 512 jobs/min` from a single worker.

### Important: Ollama must support parallel requests

Check if Ollama is configured for parallel inference:
```bash
OLLAMA_NUM_PARALLEL=4   # Must be set in Ollama's environment
OLLAMA_MAX_LOADED_MODELS=1
```

Without this, Ollama serializes requests internally and you get no benefit from
`max_concurrent_embed_requests > 1`.

For llama.cpp server, use `--parallel 4` in the server startup arguments.

---

## Fix 4 — The `process_jobs` pipeline has a sequencing bug under load

In `worker.rs`, `process_jobs` pipelines prepare/embed/complete across chunks:

```rust
for i in 0..n {
    let prepared = match next_prepare.take() { ... };
    // ... spawn next prepare
    let embedded = embed_chunk(...).await;        // AWAITED INLINE
    // ... drain previous complete_handle
    complete_handle = Some(tokio::spawn(complete_chunk(...)));
}
```

The `embed_chunk` call is awaited inline, which means **the embedding semaphore
is held for the full duration of the HTTP call, blocking the prepare of the next
chunk**. With `max_concurrent_embed_requests=1`, the pipeline actually degrades
to serial: prepare → embed → complete, with no true overlap.

### Fix: Decouple embed from the loop using a channel

This is a more significant refactor. The short-term fix is simply to increase
`max_concurrent_embed_requests` and ensure Ollama supports it (Fix 3 above).

The correct long-term pipeline is:

```
prepare_0 ──→ embed_0 ──→ complete_0
         prepare_1 ──→ embed_1 ──→ complete_1
                   prepare_2 ──→ embed_2 ──→ complete_2
```

All three stages run simultaneously with back-pressure via the semaphores.
The current implementation does achieve this but only when
`max_concurrent_embed_requests >= 2`. With the default of 1, it's purely serial.

---

## Fix 5 — `vec_complete_embedding_batch` may not exist

The README references `vec_complete_embedding_batch($1::jsonb)` as a PostgreSQL
function, and `db.rs` calls it. If this function is not defined in the schema
(it was described as a migration `V021__vec_complete_embedding_batch.sql`), every
bulk complete falls back to per-job transactions via `complete_jobs_fallback`.

**Verify:**
```sql
SELECT proname, pronargs FROM pg_proc WHERE proname = 'vec_complete_embedding_batch';
```

If it returns 0 rows, the function is missing. Every batch of 64 jobs does 64
individual `BEGIN / upsert / UPDATE / COMMIT` cycles instead of 1 batch call.
At 64 transactions × ~5ms each = 320ms pure DB overhead per chunk, completely
independent of the embedding latency.

### Check the fallback rate from logs

In your JSON logs, look for:
```
"bulk complete failed, falling back per job"
"bulk complete returned 0, falling back per job"
```

If these appear frequently, the function is missing or broken and you're paying
the per-job transaction cost on every single chunk.

### Fix: Add the missing function

```sql
CREATE OR REPLACE FUNCTION vec_complete_embedding_batch(p_payload jsonb)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_row jsonb;
  v_count integer := 0;
BEGIN
  FOR v_row IN SELECT * FROM jsonb_array_elements(p_payload)
  LOOP
    -- Upsert the embedding
    INSERT INTO vec_embeddings (
      source_table, source_key, source_observed_at, source_stream_name,
      source_sensor_id, source_location_id, source_mac,
      embedding_model, embedding_kind, embedding_dimensions,
      content_sha256, content_text, embedding, metadata,
      embedded_at, created_at, updated_at
    )
    VALUES (
      v_row->>'source_table',
      v_row->>'source_key',
      (v_row->>'source_observed_at')::timestamptz,
      v_row->>'source_stream_name',
      v_row->>'source_sensor_id',
      v_row->>'source_location_id',
      v_row->>'source_mac',
      v_row->>'embedding_model',
      v_row->>'embedding_kind',
      (v_row->>'embedding_dimensions')::int,
      v_row->>'content_sha256',
      v_row->>'content_text',
      (v_row->>'embedding')::vector,
      (v_row->>'metadata')::jsonb,
      NOW(), NOW(), NOW()
    )
    ON CONFLICT (source_table, source_key, embedding_model, embedding_kind)
    DO UPDATE SET
      source_observed_at = EXCLUDED.source_observed_at,
      content_sha256 = EXCLUDED.content_sha256,
      content_text = EXCLUDED.content_text,
      embedding = EXCLUDED.embedding,
      metadata = EXCLUDED.metadata,
      embedded_at = NOW(),
      updated_at = NOW();

    -- Mark the job completed (lease-token verified)
    UPDATE vec_embedding_jobs
    SET status = 'completed',
        content_sha256 = v_row->>'content_sha256',
        completed_at = NOW(),
        lease_token = NULL,
        leased_at = NULL,
        locked_by = NULL,
        last_error = NULL,
        updated_at = NOW()
    WHERE job_id = (v_row->>'job_id')::bigint
      AND lease_token IS NOT DISTINCT FROM v_row->>'lease_token';

    IF FOUND THEN
      v_count := v_count + 1;
    END IF;
  END LOOP;
  RETURN v_count;
END;
$$;
```

---

## Fix 6 — Run multiple worker replicas immediately

While fixes 1–5 are being deployed, run 3–4 workers in parallel. This is the
fastest way to drain the existing backlog and requires zero code changes.

Each worker needs a unique `VECTOR_EMBEDDING_WORKER_NAME`. The `FOR UPDATE SKIP LOCKED`
in `vec_lease_embedding_jobs` handles coordination automatically.

```yaml
# docker-compose or kubernetes — 4 replicas
services:
  vec-worker-1:
    environment:
      VECTOR_EMBEDDING_WORKER_NAME: worker-1
      VECTOR_EMBEDDING_BATCH_SIZE: 128
      VECTOR_EMBEDDING_REQUEST_BATCH_SIZE: 32
      VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS: 2
      POLL_INTERVAL_SECONDS: 1

  vec-worker-2:
    environment:
      VECTOR_EMBEDDING_WORKER_NAME: worker-2
      # ... same settings

  vec-worker-3:
    environment:
      VECTOR_EMBEDDING_WORKER_NAME: worker-3

  vec-worker-4:
    environment:
      VECTOR_EMBEDDING_WORKER_NAME: worker-4
```

At 4 workers × 200 jobs/min each (conservative after Fix 2+3) = **800 jobs/min**.
621K remaining / 800 = ~13 hours to drain instead of 8 days.

At 4 workers × 500 jobs/min each (after all fixes) = **2,000 jobs/min**.
621K remaining / 2,000 = **~5 hours**.

---

## Fix 7 — Re-enable `VECTOR_EMBEDDINGS_ENABLED`

This might sound obvious but: with `VECTOR_EMBEDDINGS_ENABLED=false` (the default),
the worker runs but uses placeholder model values. Verify the workers actually
have `VECTOR_EMBEDDINGS_ENABLED=true` set in production:

```bash
# Quick check — look at what the worker logs on startup
grep "worker starting" your-log-stream | jq '.enabled'
# Should be: true
```

---

## Priority order — do these in sequence today

| # | Fix | Time to implement | Expected impact |
|---|-----|-------------------|-----------------|
| **1** | Diagnose + fix behaviour_window 100% failure | 30 min | Unblocks 664 jobs, finds root cause |
| **2** | Move alert sweep to background task | 1 hour | Removes the main bottleneck — expect 2–4× throughput immediately |
| **3** | Add `vec_complete_embedding_batch` if missing | 30 min | Removes per-job transaction overhead |
| **4** | Set `max_concurrent_embed_requests=2-4` + Ollama `NUM_PARALLEL` | 15 min config | 2–4× embed throughput |
| **5** | Run 4 worker replicas | 15 min ops | Linear scaling on remaining backlog |
| **6** | Materialize `v_device_repetition_score` | 1 hour | Permanent fix so alert sweep never blocks again |
| **7** | Increase `VECTOR_EMBEDDING_BATCH_SIZE` to 256 | 5 min config | More work per poll cycle, fewer idle pauses |

---

## Expected throughput after all fixes

| Scenario | Jobs/min | Time to clear 621K backlog |
|----------|----------|---------------------------|
| Current (broken) | 55 | 8 days |
| Fix 2 only (remove alert block) | ~200 | ~52 hours |
| Fix 2 + Fix 3 (concurrency) | ~400 | ~26 hours |
| Fix 2 + 3 + 4 (bulk complete) | ~600 | ~17 hours |
| All fixes + 4 replicas | ~2,400 | **~4.3 hours** |

---

## Monitoring query to run after deploying fixes

```sql
-- Paste this and run every 60 seconds to watch progress
SELECT
  embedding_kind,
  COUNT(*) FILTER (WHERE status = 'pending') AS pending,
  COUNT(*) FILTER (WHERE status = 'leased') AS leased,
  COUNT(*) FILTER (WHERE status = 'completed') AS completed,
  COUNT(*) FILTER (WHERE status = 'failed') AS failed,
  ROUND(
    COUNT(*) FILTER (WHERE status = 'completed')::numeric /
    NULLIF(COUNT(*), 0) * 100, 1
  ) AS pct_done,
  MAX(completed_at) AS latest_completion
FROM vec_embedding_jobs
GROUP BY embedding_kind
ORDER BY embedding_kind;
```

And for live throughput (run every 30 seconds, compare delta):

```sql
SELECT
  DATE_TRUNC('minute', completed_at) AS minute,
  COUNT(*) AS completions_per_minute
FROM vec_embedding_jobs
WHERE completed_at > NOW() - INTERVAL '10 minutes'
  AND status = 'completed'
GROUP BY 1
ORDER BY 1 DESC;
```

# AI/ML Enhancement Workmap
## atheros-sensor + vec-worker — Decision-Quality Intelligence Roadmap

---

## Reading the Map

Each section maps directly to your existing architecture. Items are ordered by ROI within each track. Prerequisites are noted inline. Effort estimates assume one senior engineer.

---

## Track 1 — Behavioral Baselines Per AP/Client
**Target:** Replace static threshold rules with learned normal-behavior profiles.

### 1.1 — Per-BSSID Baseline Model (vec-worker)
**What:** For each BSSID, compute rolling statistics over `vec_behaviour_snapshots`: beacon interval variance, retry rate, signal IQR, channel dwell time, association timing.

**Where to build:**
- New table: `vec_baseline_profiles` (bssid, metric, p5, p50, p95, updated_at)
- New cron job alongside `vec_build_behaviour_snapshots()`
- New `embedding_kind = 'baseline_profile'` in `vec_embedding_jobs`

**Actionable steps:**
1. Add `vec_build_baseline_profiles()` SQL function — computes per-BSSID rolling percentiles from `sync_events` over a 7-day window.
2. Add `build_baseline_profile` arm to `text_builder.rs` `build_text()` dispatch.
3. Extend `vec_enqueue_embedding_jobs()` cron to enqueue `baseline_profile` jobs when a BSSID accumulates ≥ 50 new frames since last baseline.
4. Add `BaselineProfileRow` sqlx struct matching the new table schema.
5. Expose deviation score via new `v_bssid_anomaly_score` view: `(observed_metric - p50) / (p95 - p5)`.

**Signal to embed:** `kind: baseline_profile\nbssid: {}\nbeacon_interval_p50: {}\nretry_rate_p95: {}\nsignal_iqr: {}\n...`

---

### 1.2 — Per-Client Roaming Baseline (atheros-sensor)
**What:** Track per-client roaming paths and flag unusual transitions.

**Where to build:** `detect_state.rs` — extend `ClientInventory` / `ClientProfile`.

**Actionable steps:**
1. Add `roaming_history: Vec<(bssid, channel, observed_at)>` to `ClientProfile` (cap at 32 entries, ring-buffer).
2. Add `normal_roaming_pairs: HashSet<(String, String)>` populated after ≥ 3 observed transitions.
3. In `ClientInventory::observe()`, when a new association frame arrives with a BSSID not in `normal_roaming_pairs`, push `"threat:unusual_roam"` tag to the entry.
4. Expose roaming path in `ClientProfileSnapshot` for the `wireless.client.inventory` topic.
---
## Plan: Baseline Profile + Roaming Baseline

TL;DR: add a new `baseline_profile` embedding kind in `vec-worker` backed by a new Postgres baseline table + builder pipeline, and extend `atheros-sensor` inventory state to learn roaming pairs and flag unusual association transitions.

### Implementation Steps

1. postgres.sql
   - Add `vec_baseline_profiles` table keyed by `(bssid, metric)`
   - Extend `vec_embedding_jobs_kind_chk` to allow `'baseline_profile'`
   - Add `vec_build_baseline_profiles(...)`
     - compute per-BSSID metrics from `sync_events_expanded`
     - upsert `p5`, `p50`, `p95`, `updated_at`
   - Add `v_bssid_anomaly_score`
   - Register a new pg_cron job in `vec_install_cron_jobs()`

2. text_builder.rs
   - Add `baseline_profile` to `build_text()` and `build_text_batch()`
   - Create `BaselineProfileRow` sqlx struct
   - Implement batch builder for baseline profiles from `vec_baseline_profiles`

3. detect_state.rs
   - Add roaming history tracking to `ClientProfile`
   - Learn normal roaming pairs after ≥3 repeated transitions
   - Tag unfamiliar new association transitions with `threat:unusual_roam`
   - Expose roaming path in `ClientProfileSnapshot`

4. Compatibility check
   - Confirm oracle sink still accepts the updated client snapshot fields
   - Keep inventory output backward-compatible in oracle-worker

5. Tests
   - Add targeted SQL + Rust tests for
     - `vec_build_baseline_profiles()`
     - baseline profile text builder
     - roaming learning + unusual roam tagging

### Relevant Files
- postgres.sql
- text_builder.rs
- detect_state.rs
- wireless_alert_transform.rs

### Verification
- compile and test changed services
- verify new SQL objects and cron registration
- confirm roaming state updates and tag emission
---

## Track 2 — Sequence Models
**Target:** Detect attack chains from frame transition patterns, not just individual frames.

### 2.1 — Frame Sequence Buffer (atheros-sensor)
**What:** Track per-session ordered frame-subtype sequences and score them against known-bad patterns.

**Where to build:** New `SequenceTracker` in `detect_state.rs`, added to `PipelineState`.

**Actionable steps:**
1. Create `SequenceTracker` struct:
   ```rust
   struct SessionSequence {
       frames: VecDeque<String>,      // subtype names, cap 32
       first_seen: DateTime<Utc>,
       last_seen: DateTime<Utc>,
   }
   sessions: HashMap<String, SessionSequence>  // key = session_key
   ```
2. In `PipelineState::new()`, add `sequence_tracker: SequenceTracker`.
3. Call `sequence_tracker.observe(&entry)` in `process_packet()` after `client_inventory.observe()`.
4. Implement `SequenceTracker::check_patterns()` — returns `Option<&str>` threat tag when sequence matches:
   - `[probe_request, probe_response, deauthentication, reassociation_request, deauthentication]` → `"threat:roaming_suppression"`
   - `[auth, deauth, auth, deauth, ...]` (≥ 3 cycles in 10s) → `"threat:auth_flood"`
   - `[probe_response]` without prior `[beacon]` for that BSSID → `"threat:silent_rogue_ap"` (already partially in `RogueApTracker`, but sequence catches the stateless case)
5. Publish matched sequences to new topic `wireless.alert.sequence` (reuse `publish_oracle_json`).

---

### 2.2 — Sequence Embeddings (vec-worker)
**What:** Embed frame sequences as token strings; enable similarity search for novel attack patterns.

**Actionable steps:**
1. New table `vec_frame_sequences` — stores per-session compressed sequences (session_key, sequence_tokens, window_start, sensor_id).
2. New `embedding_kind = 'frame_sequence'` in jobs table + `build_frame_sequence` arm in `text_builder.rs`.
3. Embedding text format: `kind: frame_sequence\ntokens: BEACON AUTH ASSOC EAPOL EAPOL EAPOL EAPOL DATA_QOS\nchannel: 6\nwindow_secs: 30\n`
4. New cron `vec_build_frame_sequences()` — materializes recent sequences from `sync_events` grouped by `session_key`.
5. Add HNSW index for `embedding_kind = 'frame_sequence'` in `vec_materialize_similarity_pairs()`.

---

## Track 3 — Graph Intelligence
**Target:** Detect rogue infrastructure, hidden repeaters, and coordinated spoofing via graph structure.

### 3.1 — Infrastructure Graph Materialization (vec-worker / Postgres)
**What:** Build AP–client–SSID association graph; detect unusual topology.

**Actionable steps:**
1. New table `vec_infrastructure_graph` — edges: `(node_a, node_a_type, node_b, node_b_type, edge_type, weight, last_seen)`.
   - Edge types: `association`, `probe_target`, `roaming`, `rf_proximity`, `same_channel`
   - Node types: `bssid`, `client_mac`, `ssid`, `vendor`
2. New cron `vec_build_infrastructure_graph()` — materializes edges from `sync_events` in 1-hour windows.
3. New SQL function `vec_detect_rogue_clusters()` — flags BSSIDs where:
   - Degree centrality spikes (sudden many new clients)
   - SSID is shared across ≥ 2 BSSIDs with different OUIs
   - Client appears on ≥ 3 BSSIDs within 60s (impossible roaming speed)
4. Expose results in `vec_alerts` with `alert_type = 'rogue_cluster'` via `alerts.rs`.
5. New embedding kind `'infrastructure_subgraph'` — serialize ego-graph as text: `kind: infrastructure_subgraph\ncenter: {bssid}\nssid: {}\nclients: 14\nvendor_diversity: 3\n...`

---

### 3.2 — Channel Topology Anomaly (atheros-sensor)
**What:** Detect BSSIDs appearing on channels inconsistent with their RF neighborhood.

**Where to build:** Extend `RogueApTracker` in `detect_state.rs`.

**Actionable steps:**
1. Add `bssid_first_channel: HashMap<String, u8>` to `RogueApTracker`.
2. In `RogueApTracker::observe()`, after `channel_conflict` detection, also check: if `bssid_first_channel[bssid]` is 5GHz-range (36+) but current frame is on 2.4GHz channel (1–14), push `"channel_band_conflict"` reason.
3. Track `ap_vendor_by_bssid: HashMap<String, String>` — alert when same SSID is served by different vendor OUIs (`"vendor_conflict"` reason).

---

## Track 4 — Unsupervised Anomaly Detection
**Target:** Score "how abnormal is this AP/client" without labeled attack data.

### 4.1 — Isolation Forest Scorer (vec-worker)
**What:** Train a per-embedding-kind anomaly scorer on the stored vector space; flag outliers.

**Actionable steps:**
1. New table `vec_anomaly_scores` — (embedding_id, score, method, computed_at).
2. New cron `vec_score_anomalies()` — for each `embedding_kind`, uses pgvector's `<->` operator to compute average nearest-neighbor distance as a proxy isolation score:
   ```sql
   SELECT e.embedding_id,
          AVG(e.embedding <-> n.embedding) AS isolation_score
   FROM vec_embeddings e
   CROSS JOIN LATERAL (
     SELECT embedding FROM vec_embeddings
     WHERE embedding_kind = e.embedding_kind
       AND embedding_id != e.embedding_id
     ORDER BY embedding <-> e.embedding
     LIMIT 10
   ) n
   GROUP BY e.embedding_id;
   ```
3. Rows where `isolation_score > mean + 2.5 * stddev` → insert into `vec_alerts` with `alert_type = 'embedding_outlier'`.
4. Expose score in `vec_worker_state` metrics.
5. Wire into `alerts.rs` as `check_embedding_outliers()` alongside `check_near_duplicates()`.

---

### 4.2 — Timing Vector Anomaly (atheros-sensor)
**What:** Flag frames with impossible or scripted timing patterns.

**Where to build:** New `TimingAnomalyDetector` in `detect_state.rs`.

**Actionable steps:**
1. Track `inter_frame_deltas: HashMap<String, Vec<i64>>` (session_key → last 64 TSFT deltas in µs).
2. Compute coefficient of variation (stddev/mean) over the window.
3. Alert conditions:
   - CV < 0.02 (hyper-regular, scripted) → `"threat:scripted_timing"`
   - Delta = 0 (exact duplicate TSFT) → `"threat:replay_timing"` (complements existing `dedupe_or_replay_suspect`)
   - Delta > 500ms for a `DATA` frame session → `"threat:session_stall"`
4. Add `TimingAnomalyDetector` to `PipelineState`, observe in `process_packet()`.
5. Publish timing anomaly events to `wireless.alert.timing_anomaly`.

---

## Track 5 — RF "Language Model" (Token Prediction)
**Target:** Learn normal wireless grammar; score sequences by surprise (perplexity).

### 5.1 — Next-Event Prediction Baseline (vec-worker)
**What:** Store per-session n-gram transition counts; score new sequences by log-probability.

**Actionable steps:**
1. New table `vec_transition_model` — (prev_token, next_token, embedding_kind, count, last_updated).
   - Token = `frame_subtype` (one of ~12 values)
2. New cron `vec_update_transition_model()` — aggregates ordered `frame_subtype` sequences from `sync_events` into bigram counts (rolling 24h window).
3. New SQL function `vec_score_sequence(p_tokens text[])` → returns log-probability using Laplace-smoothed bigram model.
4. Wire into `vec_detect_rogue_clusters()` — sequences with log-prob < -15 get flagged.
5. Extend `EmbeddingInput.text` for `frame_sequence` kind to include `log_prob: {score}` so the embedding model can weight sequence rarity.

---

## Track 6 — Contextual Risk Scoring
**Target:** Replace single-signal alerts with multi-factor inference scores.

### 6.1 — Composite Risk Score (vec-worker / Postgres)
**What:** Combine deauth count, signal anomaly, SSID typosquat distance, vendor mismatch, and embedding outlier score into a single AP risk score.

**Actionable steps:**
1. New view `v_ap_risk_score`:
   ```sql
   SELECT bssid,
     (deauth_score * 0.25
      + signal_anomaly_score * 0.20
      + typosquat_score * 0.20
      + vendor_mismatch_score * 0.15
      + embedding_outlier_score * 0.20) AS composite_risk,
     ...
   FROM ... -- joins vec_anomaly_scores, vec_alerts, vec_similarity_pairs
   ```
2. Materialized as `mv_ap_risk_score`, refreshed every 5 min alongside `v_device_repetition_score`.
3. New `check_high_risk_aps()` in `alerts.rs` — inserts `alert_type = 'high_risk_ap'` when `composite_risk > 0.75`.
4. Add `composite_risk` to `vec_worker_state` metrics log every 10 iterations.

---

### 6.2 — Per-Frame Risk Tag (atheros-sensor)
**What:** Instead of binary threat tags, attach a risk score field to `AuditEntry`.

**Actionable steps:**
1. Add `risk_score: Option<f32>` to `AuditEntry` model (`model.rs`).
2. In `process_packet()`, compute `risk_score` from count of `threat:*` tags (e.g., 1 tag → 0.3, 2 → 0.6, 3+ → 0.9).
3. Include in `WirelessBandwidthEvent` — add `max_risk_score: Option<f32>` to `TrafficBucket` accumulation.
4. Downstream consumers can filter on `risk_score >= 0.6` rather than parsing tag lists.

---

## Track 7 — Time-Aware Embeddings
**Target:** Encode temporal context in embedding vectors so similar sequences at different times are handled correctly.

### 7.1 — Temporal Feature Injection (vec-worker)
**What:** Prepend time-context lines to all embedding text so vectors encode "when" not just "what."

**Actionable steps:**
1. In `event_row_to_input()` and `behaviour_row_to_input()` in `text_builder.rs`, add temporal lines after `kind: event`:
   ```
   hour_of_day: 14
   day_of_week: tuesday
   is_weekend: false
   is_business_hours: true
   ```
2. Derive from `source_observed_at` using `chrono` — add helper `fn temporal_context_lines(dt: DateTime<Utc>) -> Vec<String>`.
3. Add `burst_velocity` to behaviour_window text: `events_per_minute: {event_count / window_duration_mins:.1}`.
4. Update `content_sha256` computation to include temporal lines — triggers re-embedding on time-context changes (handled automatically by `vec_reembed_changed_jobs`).

---

### 7.2 — Burst Detection (atheros-sensor)
**What:** Detect automated/scripted behavior via inter-arrival time burstiness.

**Where to build:** Reuse `inter_arrival_p50_ms` already computed in `TrafficBucket` (`audit/bandwidth.rs`).

**Actionable steps:**
1. In `WirelessBandwidthEvent`, add `inter_arrival_cv: Option<f32>` (coefficient of variation of inter-arrival times).
2. Compute in `drain_window()` from `arrival_times_ms` reservoir (already sampled).
3. In `process_packet()`, when bandwidth events are flushed with `inter_arrival_cv < 0.05`, push `"threat:burst_automated"` to the corresponding session's next frame.
4. Include `inter_arrival_cv` in the bandwidth topic payload for downstream ML consumers.

---

## Track 8 — Device Identity Resolution
**Target:** Link randomized MACs to persistent device identities.

### 8.1 — Capability Fingerprint Correlation (atheros-sensor)
**What:** Use IE fingerprint + timing + signal continuity to group randomized MACs.

**Where to build:** New `DeviceIdentityResolver` in `detect_state.rs`.

**Actionable steps:**
1. Maintain `fingerprint_to_candidates: HashMap<String, Vec<(String, DateTime<Utc>)>>` (device_fingerprint → list of (mac, last_seen)).
2. In `process_packet()`, for each probe request: look up `device_fingerprint` in the map. If multiple MACs share the fingerprint and their last-seen times don't overlap (sequential, not concurrent), push `"identity:likely_same_device"` and `adjacent_mac_hint`-style correlation.
3. Publish correlation events to `wireless.alert.identity_correlation` when confidence ≥ 2 matching fingerprints.
4. Feed correlation into `vec_infrastructure_graph` as `edge_type = 'mac_alias'`.

---

### 8.2 — Probe Sequence Fingerprint (atheros-sensor)
**What:** Use the ordered set of probed SSIDs as a device fingerprint (devices probe a consistent SSID list).

**Where to build:** Extend `ClientInventory` in `detect_state.rs`.

**Actionable steps:**
1. Add `probe_sequence_hash: Option<String>` to `ClientProfile` — computed as SHA-256 of sorted `probe_ssids` after ≥ 5 probes.
2. Maintain `probe_hash_to_macs: HashMap<String, HashSet<String>>` at the inventory level.
3. When two MACs accumulate the same hash, push `"identity:probe_fingerprint_match"` tag and emit a correlation event.
4. Expose `probe_sequence_hash` in `ClientProfileSnapshot` for downstream use.

---

## Track 9 — Explainable AI Layer
**Target:** Every alert includes human-readable explanation alongside the score.

### 9.1 — Alert Explanation Fields (atheros-sensor)
**What:** Replace bare threat tags with structured explanation objects.

**Actionable steps:**
1. Add `explanation: Vec<AlertExplanation>` to `RogueApAlert`, `DeauthFloodAlert`, `AttackSequenceAlert`:
   ```rust
   struct AlertExplanation {
       factor: String,        // "beacon_interval_variance"
       observed: String,      // "412ms ± 89ms"
       baseline: String,      // "normal: 100ms ± 5ms"
       contribution: f32,     // 0.35
   }
   ```
2. In `RogueApTracker::observe()`, for each reason added, push a corresponding `AlertExplanation` with the observed value vs. baseline.
3. Serialize `explanation` as a JSON array in the published alert payload.
4. Consumers (the dashboard, vec-worker alert sweep) can render explanations without re-querying.

---

### 9.2 — Alert Explanation in vec-worker (vec-worker)
**What:** When `check_high_risk_aps()` fires, include factor breakdown in `vec_alerts.metadata`.

**Actionable steps:**
1. Extend `v_ap_risk_score` view to expose per-factor scores as JSONB column `factor_breakdown`.
2. In `check_high_risk_aps()` in `alerts.rs`, include `factor_breakdown` in the `metadata` insert.
3. Add `explanation_text: Option<String>` to `CompleteBatchRow` — vec-worker can optionally store a natural-language summary alongside the vector.

---

## Track 10 — Synthetic RF Simulation
**Target:** Generate labeled training data for model evaluation and rare-event coverage.

### 10.1 — Synthetic Event Generator (vec-worker / test infrastructure)
**What:** A Rust binary (or feature-flagged module) that generates realistic `sync_events` rows covering attack scenarios.

**Actionable steps:**
1. New file `services/vec-worker/src/synthetic.rs` (behind `#[cfg(feature = "synthetic")]`).
2. Implement `generate_rogue_ap_scenario(bssid, ssid, n_frames) -> Vec<SyncEventRow>` — produces interleaved beacon + deauth + reassoc frames with plausible TSFT values.
3. Implement `generate_deauth_flood(bssid, target_mac, count) -> Vec<SyncEventRow>`.
4. Implement `generate_karma_sequence(ssid, n_clients) -> Vec<SyncEventRow>` — probe_request followed by probe_response from rogue BSSID.
5. CLI subcommand `vec-worker synthetic --scenario rogue_ap --count 1000 --seed 42` — inserts rows into `sync_events` with `stream_name = 'synthetic'`.
6. Use generated data to benchmark `vec_score_anomalies()` recall on known-attack rows.

---

## Quick-Win Upgrades (1–2 days each, no new infra)

### QW-1 — `inter_arrival_cv` in bandwidth events
**File:** `audit/bandwidth.rs` — `drain_window()`. Add CV computation from existing `arrival_times_ms` reservoir. Zero new dependencies.

### QW-2 — Temporal context in embedding text
**File:** `vec-worker/src/text_builder.rs` — `event_row_to_input()`. Add 4 lines: `hour_of_day`, `day_of_week`, `is_weekend`, `is_business_hours`. Zero new dependencies.

### QW-3 — Risk score field on `AuditEntry`
**File:** `model.rs` + `parse/frame.rs` `to_audit_entry()`. Add `risk_score: Option<f32>`, compute from threat tag count. Backward-compatible (serde default = None).

### QW-4 — Alert explanation struct on existing alerts
**File:** `detect_state.rs`. Add `explanation: Vec<String>` (simplest form) to `RogueApAlert` before building the full `AlertExplanation` struct. Can be upgraded incrementally.

### QW-5 — `device_fingerprint` correlation in `ClientInventory`
**File:** `detect_state.rs` — `ClientInventory::observe()`. Already has `device_fingerprint` on `AuditEntry`. Just maintain `fingerprint_to_macs: HashMap<String, Vec<String>>` and log when a new MAC shares a fingerprint.

---

## Implementation Order

| Phase | Items | Estimated effort | Dependency |
|-------|-------|-----------------|------------|
| **Phase 0** (quick wins) | QW-1 through QW-5 | 1 week | None |
| **Phase 1** (highest ROI) | 4.2, 6.2, 7.2, 1.2, 2.1 | 3 weeks | Phase 0 |
| **Phase 2** (vec-worker enhancements) | 4.1, 7.1, 9.2, 2.2 | 3 weeks | Phase 1 |
| **Phase 3** (graph + scoring) | 3.1, 3.2, 6.1, 5.1 | 4 weeks | Phase 2 |
| **Phase 4** (advanced identity + simulation) | 1.1, 8.1, 8.2, 10.1 | 4 weeks | Phase 3 |
| **Phase 5** (sequence models) | 2.1 extension, 9.1, 5.1 extension | 3 weeks | Phase 4 |

---

## Key Invariants to Preserve

- **Wall-clock flush discipline** — any new detector in `detect_state.rs` must use `Instant`-based cooldowns (not frame timestamps) for suppress/alert decisions, matching existing `RogueApTracker` / `DeauthFloodTracker` patterns.
- **No blocking on the pcap hot path** — sequence trackers, timing detectors, and identity resolvers must be O(1) amortized per frame. Defer any O(n) computation to the inventory flush tick.
- **Backpressure-aware MAC lookup** — all new Redpanda lookups must check `backlog_pct > 80` and skip gracefully, matching the existing pattern in `process_packet()`.
- **Content SHA-256 invalidation** — any change to `text_builder.rs` that alters embedding text must be followed by running `SELECT vec_reembed_changed_jobs(p_limit => 100000)` in production to re-queue stale embeddings.
- **Alert cooldowns** — all new `vec_alerts` inserts must use the `WHERE NOT EXISTS (... created_at > NOW() - INTERVAL '1 hour')` guard matching `check_near_duplicates()`.