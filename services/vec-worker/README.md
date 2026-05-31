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
- `VECTOR_EMBEDDING_MAX_INPUT_TOKENS`
  - Default: `512`
  - Maximum estimated token count per individual input text before it is truncated at a line boundary. The character limit is derived as `max_input_tokens × 1.5` (i.e., `max_input_tokens * 3/2`), matching the `prepare_chunk` implementation which truncates at `max_input_tokens * 3 / 2` characters. Truncated texts have `[truncated]` appended. Matches the llama.cpp server default `physical_batch` (512). Increase if your provider can handle longer individual inputs (e.g., llama.cpp started with `--physical-batch 2048`).
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
  - Default: `max(prepares + completes + 4, 10)`
  - Postgres connection pool size for the worker.
- `DATABASE_POOL_MIN_CONNECTIONS`
  - Default: `1`
  - Minimum pre-warmed connections for the main worker pool. Keep this low when running several replicas against a small Postgres instance.
- `ALERT_POOL_MAX_CONNECTIONS`
  - Default: `4`
  - Connection pool size for alert sweeps. The compose vector profile sets this to `1` per worker so materialized-view refreshes cannot multiply connection pressure.
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
  - `source_table` is one of: `sync_events`, `devices`, `vec_behaviour_snapshots`, `vec_baseline_profiles`, `vec_frame_sequences`, `vec_infrastructure_graph`, `vec_timing_profiles`
  - `source_key` is the primary key value of that row as text
- `embedding_model` — model name used for this job
- `embedding_kind` — one of `event`, `device`, `behaviour_window`, `baseline_profile`, `frame_sequence`, `infrastructure_subgraph`, `timing_profile`
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
- pgvector HNSW indexes for `embedding_kind` / `embedding_model` / `embedding_dimensions = 768` for event/device/behaviour_window/frame_sequence/timing_profile

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
VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES=8
DATABASE_POOL_MAX_CONNECTIONS=20
DATABASE_POOL_MIN_CONNECTIONS=1
ALERT_POOL_MAX_CONNECTIONS=2
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

The vec-worker is a **consumer** of embedding jobs - it never creates them, and it never builds the behaviour snapshots it reads. Both are produced by Postgres cron jobs defined in `vec_install_cron_jobs()` at `sql/cron/001_vec_install_cron_jobs.sql` (and included by the `sql/postgres.sql` shim). `pg_cron` must be installed and the `cron` schema available.

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
sql/cron/001_vec_install_cron_jobs.sql  ->  vec_install_cron_jobs()
```

The individual functions (`vec_enqueue_embedding_jobs`, `vec_build_behaviour_snapshots`, `vec_materialize_similarity_pairs`, `vec_release_expired_leases`, `vec_reap_stale_workers`) are defined in the same file, lines 1175–2002.

## Relevant source files

- `services/vec-worker/src/main.rs` — startup, CLI, logging, and process entry point
- `services/vec-worker/src/config.rs` — environment variable parsing and validation
- `services/vec-worker/src/worker.rs` — leasing loop, batch processing, job lifecycle, shutdown
- `services/vec-worker/src/db.rs` — Postgres access, job update, embedding upsert, worker heartbeat
- `services/vec-worker/src/text_builder.rs` — source row reads and embedding text construction

- `sql/postgres.sql` (shim) and split `sql/*` files — Postgres table definitions and helper functions used by the worker

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

# vec-worker: Frame Sequences & Null Column Fix Workmap

**Scope:** `vec_frame_sequences` empty, `vec_transition_model` empty, null columns
propagating from `wireless_authorized_networks` / `sync_events_expanded` into
embedded text and alert logic.

---

# vec-worker Intelligence Workmap
## From Noisy Deduplication → Actionable Device Intelligence

**Status as of 2026-05-26**

The similarity pipeline is working at the event level (cosine distance 0.017–0.035 on
`event_event` pairs is real signal). The problems are architectural: the things that
matter most — device identity across MACs, frame sequence anomaly scoring, and the
`v_device_repetition_score` view — are either empty or producing noise the rest of the
stack can't consume. This document is a bottom-up fix plan with no repetition and
no wishful thinking.

---

## Why `v_device_repetition_score` Is Empty

This is the most important thing to fix first, because every downstream alert and
dashboard depends on it.

The view queries `vec_similarity_pairs` for `event_event` pairs and groups by
`source_mac`. The data above shows `event_event` pairs *do exist*, all associated
with MAC `30:93:bc:81:b3:de`. But the view is empty. The reason is almost certainly
one of:

1. **`left_source_mac` / `right_source_mac` are NULL** in the similarity pairs rows,
   even though the events themselves have `source_mac` populated. The builder uses
   `COALESCE(sensor_id, payload->>'sensor_id')` for sensor but the MAC fields come from
   `sync_events_expanded.source_mac` — if that column was null at embedding time, the
   similarity pair stored a null MAC and the `GROUP BY source_mac` collapses to nothing.

2. **The materialized view refresh is failing silently** because
   `REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score` requires a unique
   index on `source_mac`. If that index was added after the first refresh created the
   view without it, concurrent refresh throws an error that `run_alert_sweep` swallows
   with a `warn!` and continues.

**Diagnostic queries to run first:**

```sql
-- 1. Confirm MAC fields in the pairs that exist
SELECT
  pair_id,
  left_source_mac,
  right_source_mac,
  left_source_table,
  cosine_distance
FROM vec_similarity_pairs
WHERE pair_kind = 'event_event'
LIMIT 10;
1	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0000000596046394
2	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.007044434547424316
3	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0000001192092896
4	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0000001192092807
5	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0
6	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0
7	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0
8	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0
9	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0
10	a4:97:33:fb:af:fb	a4:97:33:fb:af:fb	sync_events	0.0

-- 2. Confirm the unique index exists
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'v_device_repetition_score';
idx_v_device_repetition_score_mac	CREATE UNIQUE INDEX idx_v_device_repetition_score_mac ON public.v_device_repetition_score USING btree (source_mac)
-- 3. Try a manual non-concurrent refresh to surface the real error
REFRESH MATERIALIZED VIEW v_device_repetition_score;
Updated Rows	0
Execute time	0.936s
Start time	Tue May 26 21:08:21 EDT 2026
Finish time	Tue May 26 21:08:22 EDT 2026
Query	SELECT
	  pair_id,
-- 4. Confirm what the view actually queries
SELECT pg_get_viewdef('v_device_repetition_score', true);
```
 WITH device_pairs AS (
         SELECT p.left_source_mac AS source_mac,
            p.cosine_distance,
            p.left_embedding_id AS embedding_id,
            p.computed_at
           FROM vec_similarity_pairs p
          WHERE p.pair_kind = 'event_event'::text AND p.cosine_distance < 0.05::double precision AND p.left_source_mac IS NOT NULL
        UNION ALL
         SELECT p.right_source_mac AS source_mac,
            p.cosine_distance,
            p.right_embedding_id AS embedding_id,
            p.computed_at
           FROM vec_similarity_pairs p
          WHERE p.pair_kind = 'event_event'::text AND p.cosine_distance < 0.05::double precision AND p.right_source_mac IS NOT NULL
        )
 SELECT source_mac,
    count(*) AS near_duplicate_pairs,
    min(cosine_distance) AS min_distance,
    avg(cosine_distance) AS avg_distance,
    count(DISTINCT embedding_id) AS unique_events_implicated
   FROM device_pairs
  WHERE computed_at >= (now() - '24:00:00'::interval)
  GROUP BY source_mac
  ORDER BY (count(*)) DESC;
**Fix A — if MACs are NULL in similarity pairs:**

The `vec_complete_embedding_batch` function populates `source_mac` from
`CompleteBatchRow.source_mac`, which comes from `EmbeddingInput.source_mac`,
which comes from `event_row_to_input` → `LOWER(COALESCE(source_mac, payload->>'source_mac'))`.

If this is NULL it means `sync_events_expanded` has no `source_mac` column or it
was empty at the time. Check:

```sql
SELECT
  dedupe_key,
  source_mac,
  payload->>'source_mac' AS payload_mac
FROM sync_events_expanded
WHERE dedupe_key = 'becd69ee37f8d9ca345f08ebe06b93447cb0a75d241e70d45628982cd8ecf38e';
```

If the column is there but the already-embedded rows have null MACs in
`vec_embeddings`, re-embed them:

```sql
-- Mark affected embeddings for re-embedding
UPDATE vec_embedding_jobs
SET status = 'pending',
    due_at = now(),
    lease_token = NULL,
    leased_at = NULL,
    locked_by = NULL,
    last_error = 'mac_null_reembed'
WHERE source_table = 'sync_events'
  AND source_key IN (
    SELECT source_key FROM vec_embeddings
    WHERE embedding_kind = 'event'
      AND source_mac IS NULL
  );
```

**Fix B — if the concurrent refresh index is missing:**

```sql
-- Check if the matview has a unique index
\d v_device_repetition_score

-- If not, create one (adjust column name to match actual schema):
CREATE UNIQUE INDEX v_device_repetition_score_mac_idx
ON v_device_repetition_score (source_mac);
```

---

## Device Identity Across Multiple MACs

This is the core intelligence gap. A device using MAC randomization (all those
`a2:`, `6a:`, `be:`, `c6:` prefixed locally-administered MACs in the behaviour
window data) shows up as dozens of independent "devices" when it's one physical
device. The vec system has all the signal needed to fix this — it's just not wired up.

### What the data already contains

The behaviour window data shows the pattern clearly:

- `6a:6f:a4:d7:40:18` — management frame, signal -88 dBm, `unknown` protocol
- `a2:36:dd:55:ef:f6` — management frame, signal -70 dBm
- `be:10:79:73:db:06` — management frame, signal -75 dBm
- `a6:15:d2:01:19:fc` — management frame, signal -82 dBm
- `c6:bb:84:35:f2:a9` — data frames, signal -90 dBm, **fully protected**

The second bit of each MAC's first octet being `1` means locally administered
(i.e., randomized). Multiple randomized MACs at similar signal strengths in the same
15-minute window, same sensor, same location — this is one device probing under
different identities.

The `mac_rotation_indicators` JSONB field in `vec_behaviour_snapshots` exists for
exactly this. The question is whether it's being populated.

### Track 1 — Populate `mac_rotation_indicators` correctly

The field should contain signals that let the model (and similarity search) recognize
rotation patterns. Currently it likely stores ratio values but not the cross-MAC
linking signals.

**What to store in `mac_rotation_indicators`:**

```json
{
  "is_locally_administered": true,
  "la_mac_count_in_window": 4,
  "signal_dbm_range": 18,
  "concurrent_la_macs_same_sensor": ["6a:6f:a4:d7:40:18", "a2:36:dd:55:ef:f6"],
  "oui_vendor": null,
  "rotation_confidence": 0.87
}
```

The rotation confidence can be computed from:
- All four MACs being LA (`is_locally_administered` bit set) → high signal
- Signal strength variance < 20 dBm across MACs → same physical location
- Temporal overlap in the same 15-minute window → likely same device
- No SSID association (management frames only, no data) → still probing

**SQL change in `vec_build_behaviour_snapshots`:**

```sql
-- In the CTE that builds mac_rotation_indicators, add:
jsonb_build_object(
  'is_locally_administered',
    bool_and((get_byte(decode(split_part(source_mac, ':', 1), 'hex'), 0) & 2) = 2),
  'la_mac_count_in_window',
    COUNT(DISTINCT source_mac) FILTER (
      WHERE (get_byte(decode(split_part(source_mac, ':', 1), 'hex'), 0) & 2) = 2
    ),
  'signal_range_dbm',
    MAX(signal_dbm) - MIN(signal_dbm),
  'rotation_confidence',
    CASE
      WHEN COUNT(DISTINCT source_mac) >= 3
       AND (MAX(signal_dbm) - MIN(signal_dbm)) < 20
      THEN ROUND(LEAST(1.0, COUNT(DISTINCT source_mac)::numeric / 5), 2)
      ELSE 0
    END
) AS mac_rotation_indicators
```

### Track 2 — Cross-MAC device grouping table

The vector similarity approach (embedding behaviour windows and finding near-duplicates)
is the right direction, but the output needs a concrete grouping table, not just pairs.

**New table: `device_identity_clusters`**

```sql
CREATE TABLE device_identity_clusters (
  cluster_id          bigserial PRIMARY KEY,
  canonical_mac       text NOT NULL,        -- most-seen or oldest MAC in group
  member_macs         text[] NOT NULL,      -- all MACs believed to be same device
  confidence          numeric(5,4) NOT NULL,
  evidence_kind       text NOT NULL,        -- 'signal_proximity', 'sequence_similarity', 'behaviour_match'
  sensor_id           text,
  location_id         text,
  first_seen          timestamptz,
  last_seen           timestamptz,
  created_at          timestamptz DEFAULT now(),
  updated_at          timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX device_identity_clusters_canonical_idx
  ON device_identity_clusters (canonical_mac);

CREATE INDEX device_identity_clusters_member_idx
  ON device_identity_clusters USING GIN (member_macs);
```

**Population function: `vec_build_device_clusters()`**

The logic:

1. Find all `behaviour_window` pairs in `vec_similarity_pairs` where
   `cosine_distance < 0.15` (behaviour windows that look nearly identical).
2. For each pair where both MACs are locally administered, check signal proximity
   (within 15 dBm) and same sensor/location/window overlap.
3. Use union-find to group transitively connected MACs.
4. Upsert into `device_identity_clusters`.

```sql
CREATE OR REPLACE FUNCTION vec_build_device_clusters(
  p_distance_threshold numeric DEFAULT 0.15,
  p_signal_threshold   numeric DEFAULT 15.0
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_inserted integer := 0;
BEGIN
  WITH candidate_pairs AS (
    SELECT
      sp.left_source_mac  AS mac_a,
      sp.right_source_mac AS mac_b,
      sp.cosine_distance,
      le.source_sensor_id,
      le.source_location_id,
      ABS(
        (le.metadata->>'signal_avg_dbm')::numeric -
        (re.metadata->>'signal_avg_dbm')::numeric
      ) AS signal_delta
    FROM vec_similarity_pairs sp
    JOIN vec_embeddings le ON le.embedding_id = sp.left_embedding_id
    JOIN vec_embeddings re ON re.embedding_id = sp.right_embedding_id
    WHERE sp.pair_kind = 'behaviour_behaviour'
      AND sp.cosine_distance < p_distance_threshold
      AND sp.left_source_mac IS NOT NULL
      AND sp.right_source_mac IS NOT NULL
      AND sp.left_source_mac <> sp.right_source_mac
      -- Both locally administered
      AND (get_byte(decode(split_part(sp.left_source_mac,  ':', 1), 'hex'), 0) & 2) = 2
      AND (get_byte(decode(split_part(sp.right_source_mac, ':', 1), 'hex'), 0) & 2) = 2
  ),
  filtered AS (
    SELECT mac_a, mac_b, source_sensor_id, source_location_id
    FROM candidate_pairs
    WHERE signal_delta <= p_signal_threshold
       OR signal_delta IS NULL  -- missing signal is neutral, not disqualifying
  ),
  -- Simple grouping: treat each pair as an edge, pick the lexicographically
  -- smallest MAC as canonical for this batch.
  grouped AS (
    SELECT
      LEAST(mac_a, mac_b) AS canonical_mac,
      array_agg(DISTINCT mac_a ORDER BY mac_a) ||
      array_agg(DISTINCT mac_b ORDER BY mac_b) AS raw_members,
      source_sensor_id,
      source_location_id,
      COUNT(*) AS evidence_count
    FROM filtered
    GROUP BY LEAST(mac_a, mac_b), source_sensor_id, source_location_id
  )
  INSERT INTO device_identity_clusters (
    canonical_mac, member_macs, confidence,
    evidence_kind, sensor_id, location_id,
    created_at, updated_at
  )
  SELECT
    canonical_mac,
    ARRAY(SELECT DISTINCT unnest(raw_members) ORDER BY 1),
    LEAST(1.0, evidence_count::numeric / 5),
    'behaviour_match',
    source_sensor_id,
    source_location_id,
    now(), now()
  FROM grouped
  ON CONFLICT (canonical_mac) DO UPDATE SET
    member_macs = EXCLUDED.member_macs,
    confidence  = EXCLUDED.confidence,
    updated_at  = now();

  GET DIAGNOSTICS v_inserted = ROW_COUNT;
  RETURN v_inserted;
END;
$$;
```

Schedule in `vec_install_cron_jobs()`:

```sql
PERFORM cron.schedule(
  'vec-build-device-clusters',
  '*/10 * * * *',
  $cron$SELECT vec_build_device_clusters();$cron$
);
```

### Track 3 — Surface clusters in the Rust worker

In `text_builder.rs`, the `build_device` function currently only looks at the single
`devices` row. It should also pull from `device_identity_clusters` and include the
cluster context:

```rust
// After fetching the device row, check for cluster membership
let cluster = sqlx::query!(
    r#"
    SELECT canonical_mac, member_macs, confidence
    FROM device_identity_clusters
    WHERE canonical_mac = $1
       OR $1 = ANY(member_macs)
    "#,
    &job.source_key
)
.fetch_optional(pool)
.await
.ok()
.flatten();

if let Some(c) = cluster {
    lines.push(format!("identity_cluster_size: {}", c.member_macs.len()));
    lines.push(format!("identity_confidence: {:.2}", c.confidence));
    // Don't include the actual MACs — identity-stripped means no MAC leakage
}
```

---

## Frame Sequences — Making Them Actually Useful

The current state (per the existing workmap) is that `vec_frame_sequences` is empty
because the cron job was never registered. After the rename fix (Fix 1 in the prior
document) populates the table, the sequences will still produce garbage scores because
`vec_transition_model` is empty. Here's how to make the sequences meaningful once the
table is populated.

### What a useful frame sequence actually looks like

The behaviour window data shows the problem directly:

```text
6a:6f:a4:d7:40:18 — 1 event, management, unknown protocol
a2:36:dd:55:ef:f6 — 1 event, management, unknown protocol
c6:bb:84:35:f2:a9 — 2 events, data, unknown protocol, fully protected
```

A sequence of `[PROBE_REQ, PROBE_REQ, ASSOC_REQ, EAPOL, DATA_QOS]` is normal
802.11 association. A sequence of `[PROBE_REQ, AUTH, DEAUTH, AUTH, DEAUTH, AUTH]`
is a deauth attack or a client fighting for a connection. A sequence of
`[BEACON, BEACON, BEACON, ...(200 times)]` is a rogue AP flooding.

The `sequence_tokens` field needs to store *meaningful* tokens — frame subtypes,
not just frame types. The `rogue_cluster` alerts above show exactly this:
`62:e1:1d:2e:c6:f4` has `log_prob: -246` against a threshold of -15, which is
a real anomaly (a 231-sigma sequence). But it only triggered because the transition
model was seeded. The issue is reproducibility.

### Track 4 — Normalize sequence token vocabulary

The transition model is only useful if the token vocabulary is stable and small.
Currently `sequence_tokens` is likely raw frame subtypes from the payload, which
includes numeric codes, vendor-specific strings, and mixed case.

**Normalized token mapping (add to `vec_build_frame_sequences`):**

```sql
-- In the prepared CTE, replace raw frame_subtype with a normalized token:
CASE
  WHEN frame_subtype ILIKE '%probe_req%'    THEN 'PROBE_REQ'
  WHEN frame_subtype ILIKE '%probe_resp%'   THEN 'PROBE_RESP'
  WHEN frame_subtype ILIKE '%beacon%'       THEN 'BEACON'
  WHEN frame_subtype ILIKE '%auth%'
   AND frame_subtype NOT ILIKE '%deauth%'   THEN 'AUTH'
  WHEN frame_subtype ILIKE '%deauth%'       THEN 'DEAUTH'
  WHEN frame_subtype ILIKE '%assoc_req%'    THEN 'ASSOC_REQ'
  WHEN frame_subtype ILIKE '%assoc_resp%'   THEN 'ASSOC_RESP'
  WHEN frame_subtype ILIKE '%reassoc%'      THEN 'REASSOC'
  WHEN frame_subtype ILIKE '%disassoc%'     THEN 'DISASSOC'
  WHEN frame_subtype ILIKE '%eapol%'        THEN 'EAPOL'
  WHEN frame_subtype ILIKE '%data%'
   AND frame_type   ILIKE '%data%'          THEN 'DATA'
  WHEN frame_subtype ILIKE '%null%'         THEN 'NULL_DATA'
  WHEN frame_subtype ILIKE '%action%'       THEN 'ACTION'
  ELSE 'OTHER'
END AS normalized_token
```

With a vocabulary of ~13 tokens, the transition model converges quickly and scores
are meaningful. Without normalization, every new vendor string creates a new bigram
that will never have count > 1 and scores collapse to uniform.

### Track 5 — Alert threshold calibration

The current threshold of `-15` is too tight for the normalized vocabulary. With 13
tokens and real traffic, a normal 10-frame sequence scores around `-20` to `-35`
(log probability of 10 bigrams, each ~0.1–0.2 probability). The `-246` score for
`62:e1:1d:2e:c6:f4` is genuinely anomalous.

After normalizing the vocabulary and rebuilding the transition model:

```sql
-- Calibrate threshold from real data
SELECT
  percentile_cont(0.95) WITHIN GROUP (ORDER BY (metadata->>'log_prob')::numeric) AS p95,
  percentile_cont(0.99) WITHIN GROUP (ORDER BY (metadata->>'log_prob')::numeric) AS p99,
  AVG((metadata->>'log_prob')::numeric) AS avg_score,
  STDDEV((metadata->>'log_prob')::numeric) AS stddev_score
FROM vec_similarity_pairs
WHERE pair_kind = 'sequence_sequence';
```

Set the alert threshold to `mean - 3*stddev` of the real distribution.
Update `vec_detect_rogue_clusters()` accordingly.

---

## What Makes the Similarity Pairs Actually Valuable

The `event_event` pairs for `30:93:bc:81:b3:de` at cosine distances 0.017–0.035
are excellent — these are the same device (Spectrum router/modem based on SSID
`MySpectrumWiFid8-2G`) sending near-identical beacon/probe responses ~20–40 seconds
apart. This is normal AP behavior. The current threshold of `0.05` catches these.

What the system **should** be doing with this but isn't:

### Track 6 — Distinguish normal repetition from attack repetition

The near-duplicate sweep marks everything above the threshold as a
`near_duplicate_cluster` alert. But an AP sending beacons every 100ms is expected.
What's anomalous is:

- A *client* (not AP) sending near-duplicate management frames rapidly
- A device with a *randomized MAC* sending near-duplicate frames (suggests scripted attack)
- Near-duplicate frames from *different* MACs (suggests MAC spoofing)

**Add `source_mac_is_ap` classification to similarity pairs:**

```sql
-- In vec_materialize_similarity_pairs, add to the evidence JSONB:
jsonb_build_object(
  'detector', 'near_duplicate_event',
  'threshold', 0.05,
  'left_mac_is_la',  (get_byte(decode(split_part(left_source_mac,  ':', 1), 'hex'), 0) & 2) = 2,
  'right_mac_is_la', (get_byte(decode(split_part(right_source_mac, ':', 1), 'hex'), 0) & 2) = 2,
  'is_cross_mac',    left_source_mac <> right_source_mac
)
```

Then in `check_near_duplicates`, filter the alert by whether the repetition is
suspicious:

```sql
-- Only alert when the repeating device has a locally-administered MAC
-- OR when events come from different MACs (cross-MAC duplicate = spoofing suspect)
WHERE near_duplicate_pairs >= $1
  AND (
    -- LA MAC repeating its own frames rapidly
    (metadata->>'left_mac_is_la')::boolean = true
    -- OR different MACs sending identical frames (spoofing / replay)
    OR (metadata->>'is_cross_mac')::boolean = true
  )
```

This will clear the false-positive noise from `30:93:bc:81:b3:de` (a stable AP with
a manufacturer MAC sending normal beacons) while keeping alerts for the randomized
MACs in the behaviour window data.

### Track 7 — `high_risk_ap` score decomposition

Alert 1145 for `ee:fc:2d:6c:df:24` has `deauth_score: 21.2` and `composite_risk: 5.3`
but `typosquat_score: 0`, `vendor_mismatch_score: 0`, `embedding_outlier_score: 0`.
The risk is entirely from deauth frames. The alert is real but the score decomposition
in the metadata is more useful than the composite alone.

**Change the alert text in `check_high_risk_aps` to include the dominant signal:**

```rust
// In alerts.rs, after inserting the alert, add a structured explanation:
let dominant = find_dominant_risk_factor(&metadata);
// → "deauth_storm" / "typosquatting" / "vendor_mismatch" / "outlier_embedding"
info!(
    source_mac = mac,
    dominant_risk = dominant,
    composite_risk,
    "high-risk AP alert inserted"
);
```

This also feeds the `explanation_text` field in `CompleteBatchRow` which currently
sits unused (always `None`).

---

## Implementation Order

Ordered by: fix broken things first, then add signal, then refine.

| # | Track | Change | Risk | Expected outcome |
|---|-------|--------|------|-----------------|
| 1 | Diagnostic | Run the 4 diagnostic queries for `v_device_repetition_score` | None | Identify whether MAC-null or missing index is the root cause |
| 2 | Fix A or B | Fix MAC propagation **or** create unique index | Low | `v_device_repetition_score` becomes non-empty |
| 3 | Frame seqs | Apply prior workmap Fix 1–4 (rename, cron, column COALESCE, null-safe) | Medium | `vec_frame_sequences` starts populating |
| 4 | Track 4 | Normalize frame sequence vocabulary to 13-token set | Low | Transition model scores become meaningful |
| 5 | Track 5 | Rebuild transition model, calibrate alert threshold | None | Rogue cluster alerts become reliable |
| 6 | Track 1 | Improve `mac_rotation_indicators` in snapshot builder | Low | Behaviour window embeddings carry rotation signal |
| 7 | Track 2 | Add `device_identity_clusters` table and function | Medium | MAC-rotated devices tracked as single identity |
| 8 | Track 3 | Surface cluster context in device text builder | Low | Device embeddings include cluster-size signal |
| 9 | Track 6 | Filter near-duplicate alerts by LA-MAC / cross-MAC | Low | Eliminates AP beacon noise from alerts |
| 10 | Track 7 | Populate `explanation_text` in high-risk AP alerts | Low | Alert metadata becomes actionable |

---

## Verification After Each Track

```sql
-- After Track 2: confirm repetition score has rows
SELECT COUNT(*), AVG(near_duplicate_pairs) FROM v_device_repetition_score;

-- After Track 3+4: confirm sequences have normalized tokens
SELECT DISTINCT unnest(string_to_array(sequence_tokens, ' ')) AS token
FROM vec_frame_sequences LIMIT 30;
-- Should return only the 13 normalized tokens

-- After Track 5: confirm transition model is non-trivial
SELECT COUNT(*) FROM vec_transition_model;
SELECT SUM(count) AS total_bigrams FROM vec_transition_model;
-- Expect > 1000 bigrams for a healthy model

-- After Track 6: confirm rotation indicators are populated
SELECT
  source_mac,
  mac_rotation_indicators->>'la_mac_count_in_window' AS la_count,
  mac_rotation_indicators->>'rotation_confidence'    AS confidence
FROM vec_behaviour_snapshots
WHERE (mac_rotation_indicators->>'la_mac_count_in_window')::int > 1
ORDER BY confidence DESC
LIMIT 20;

-- After Track 7: confirm device clusters are forming
SELECT
  canonical_mac,
  array_length(member_macs, 1) AS cluster_size,
  confidence
FROM device_identity_clusters
ORDER BY cluster_size DESC
LIMIT 10;

-- After Track 9: confirm near-duplicate alerts no longer fire for stable APs
SELECT source_mac, COUNT(*) AS alert_count
FROM vec_alerts
WHERE alert_type = 'near_duplicate_cluster'
  AND created_at > now() - interval '1 hour'
GROUP BY source_mac
ORDER BY alert_count DESC;
-- Stable AP MACs like 30:93:bc:81:b3:de should not appear here
```

---

## The Actual Goal

After all tracks are complete:

- A device using MAC randomization (like the `6a:`, `a2:`, `be:`, `a6:` MACs in the
  behaviour data) will appear as **one entry** in `device_identity_clusters` with
  confidence proportional to how many matching signals exist.
- `v_device_repetition_score` will be non-empty and will correctly distinguish
  a stable AP (high repetition, low risk) from a randomized client sending
  near-duplicate probes (high risk).
- Frame sequences will score anomalies against a calibrated baseline, so
  the `-246` log-prob for `62:e1:1d:2e:c6:f4` means something and the
  alert fires reliably instead of intermittently.
- The `high_risk_ap` alert for `ee:fc:2d:6c:df:24` will include a human-readable
  explanation of *why* it scored high (`deauth_storm`), not just a number.
