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

# vec-worker: Frame Sequences & Null Column Fix Workmap

**Scope:** `vec_frame_sequences` empty, `vec_transition_model` empty, null columns
propagating from `wireless_authorized_networks` / `sync_events_expanded` into
embedded text and alert logic.

---

## Root Cause Inventory

### RC-1 — `vec_build_baseline_profiles` is defined twice and clobbers `vec_frame_sequences` population

`postgres.sql` contains **two `CREATE OR REPLACE FUNCTION vec_build_baseline_profiles`**
definitions. The first one (lines ~1990–2030) is actually the frame sequence builder —
it inserts into `vec_frame_sequences` — but it is named `vec_build_baseline_profiles`
with the signature `(p_from, p_to)`. The second definition (lines ~2050+) is the real
baseline profile builder with `(p_from, p_to, p_window)`.

Because the second definition has a different signature, **both functions coexist**.
The cron job registered as `vec-build-baseline-profiles` calls
`vec_build_baseline_profiles()` (zero args), which resolves to whichever overload
PostgreSQL picks — in practice neither populates `vec_frame_sequences` because the
cron name and the function name are mismatched: the cron job that should call the
frame-sequence builder does not exist.

The `vec_install_cron_jobs()` block registers:
- `vec-build-baseline-profiles` → `vec_build_baseline_profiles()` ✓ (baseline)
- **No cron job exists for `vec_build_frame_sequences()`** ✗

`vec_frame_sequences` is therefore **never populated by any cron job**.

### RC-2 — `vec_enqueue_embedding_jobs` enqueues `frame_sequence` jobs against `session_key` but the builder mismatches

`vec_enqueue_embedding_jobs` does not enqueue `frame_sequence` jobs at all — there is
no `frame_sequence_jobs` CTE in the function body. The `text_builder.rs` dispatches on
`"frame_sequence"` but no jobs are ever created, so the builder is dead code.

### RC-3 — `wireless_authorized_networks` columns surface as null in `sync_events_expanded`

`sync_events_expanded` is a plain view joining `sync_events` and `wireless_frames`.
`wireless_frames` stores `location_id` and `sensor_id` as nullable text, populated via
`coordinator.upsert_wireless_frame_from_payload` using `nullif(payload->>'...', '')`.

When the sensor does not send `location_id` or `sensor_id` in the payload (older schema
versions, or the field is empty string), the columns are null in both `wireless_frames`
and consequently in `sync_events_expanded`. The behaviour snapshot builder, text
builder, and alert functions all use `COALESCE(column, payload->>'column')` — but if
the payload field is also absent or empty, null propagates into:

- `vec_behaviour_snapshots.location_id` / `sensor_id`
- `vec_frame_sequences.location_id` / `sensor_id`
- `EmbeddingInput.source_sensor_id` / `source_location_id`
- `CompleteBatchRow.source_sensor_id` / `source_location_id`
- `vec_alerts.sensor_id` / `location_id`

The `wireless_authorized_networks` table is unrelated to the null propagation — it is
only consulted by `coordinator.generate_shadow_alerts()` for authorized-network
lookups. Its `location_id` being null is intentional (null = match any location). The
confusion likely arises because `v_device_repetition_score` and `v_ap_risk_score` join
through `vec_similarity_pairs` which stores null `left_sensor_id` / `right_sensor_id`
when the source row had null values.

### RC-4 — `vec_transition_model` is never populated before `vec_score_sequence` is called

The cron job `vec-update-transition-model` is registered (every 15 min) but
`vec_update_transition_model()` aggregates from `sync_events_expanded` using
`payload->>'frame_subtype'`. The `frame_subtype` field is stored in
`wireless_frames.frame_subtype` but the expanded view accesses it as
`payload->>'frame_subtype'` (JSONB extraction). If the field was inserted into
the `wireless_frames` column (not left in the payload JSONB), the extraction
returns null and the CTE produces zero rows, so the model stays empty.

In `text_builder.rs`, `build_frame_sequences_batch` calls
`vec_score_sequence(regexp_split_to_array(sequence_tokens, E'\\s+'))` inline in
the SQL — this returns `0.0` for every sequence when the transition model is empty
(the vocab-size fallback sets `v_vocab_size = 16` but all bigram counts are 0, so
every bigram gets uniform probability and the log-prob is non-zero but meaningless).
The bigger issue is that with an empty `vec_frame_sequences`, no jobs are ever created
for this kind.

### RC-5 — `build_ego_graph_input` produces a Cartesian-product LATERAL that can generate duplicate `query_key` rows

In `build_infrastructure_subgraphs_batch`, the LATERAL subquery emitting `endpoint`
unions `node_a` and `node_b` for every matching row, which means a single edge where
both `node_a` and `node_b` are in the key set generates **two rows** with the same
underlying edge data but different `query_key` values. This is correct for grouping
but means the `grouped` HashMap accumulates duplicate edge structs, inflating client /
vendor counts in the embedded text.

---

## Fix Workmap

Each fix is independent. Order follows impact.

---

### Fix 1 — Add the missing `vec_build_frame_sequences` cron job and rename the mislabeled function

**Files:** `sql/postgres.sql`

**Problem:** The first overload of `vec_build_baseline_profiles(p_from, p_to)` is
actually a frame-sequence builder (it inserts into `vec_frame_sequences`). It is
never called by the cron schedule. The real baseline builder is the second overload.

**Steps:**

1. Rename the first `vec_build_baseline_profiles(p_from, p_to)` function to
   `vec_build_frame_sequences(p_from, p_to)` throughout the file.

2. Drop the old mislabeled overload before creating the renamed one:

```sql
DROP FUNCTION IF EXISTS vec_build_baseline_profiles(timestamptz, timestamptz);

CREATE OR REPLACE FUNCTION vec_build_frame_sequences(
  p_from timestamptz DEFAULT now() - interval '2 hours',
  p_to   timestamptz DEFAULT now()
)
RETURNS integer
LANGUAGE plpgsql
AS $$
-- (body unchanged — same INSERT INTO vec_frame_sequences CTE)
$$;
```

3. In `vec_install_cron_jobs()`, add the missing schedule:

```sql
PERFORM cron.schedule(
  'vec-build-frame-sequences',
  '*/5 * * * *',
  $cron$SELECT vec_build_frame_sequences();$cron$
);
```

4. Verify no other callers reference the old name:

```sql
SELECT proname, pronargs, proargtypes
FROM pg_proc
WHERE proname = 'vec_build_baseline_profiles';
-- Should return exactly one row (the 3-arg baseline version)
```

---

### Fix 2 — Add `frame_sequence` job enqueuing to `vec_enqueue_embedding_jobs`

**Files:** `sql/postgres.sql`

**Problem:** `vec_enqueue_embedding_jobs` has no CTE for `frame_sequence` jobs, so
`vec_frame_sequences` rows are never queued for embedding even after Fix 1 populates
the table.

**Steps:**

Add a `frame_sequence_jobs` CTE inside `vec_enqueue_embedding_jobs`, mirroring the
`behaviour_jobs` pattern:

```sql
frame_sequence_jobs AS (
  SELECT
    'vec_frame_sequences'::text AS source_table,
    fs.session_key               AS source_key,
    p_model                      AS embedding_model,
    'frame_sequence'::text       AS embedding_kind,
    18                           AS priority
  FROM vec_frame_sequences fs
  LEFT JOIN vec_embeddings existing
    ON existing.source_table  = 'vec_frame_sequences'
   AND existing.source_key    = fs.session_key
   AND existing.embedding_model = p_model
   AND existing.embedding_kind  = 'frame_sequence'
  WHERE existing.embedding_id IS NULL
     OR fs.updated_at > existing.embedded_at
),
```

Then include `frame_sequence_jobs` in the final UNION inside `jobs`:

```sql
UNION ALL
SELECT * FROM frame_sequence_jobs
```

---

### Fix 3 — Fix `vec_update_transition_model` to read from the column, not just the payload

**Files:** `sql/postgres.sql`

**Problem:** The function uses `payload->>'frame_subtype'` but `frame_subtype` is a
parsed column on `wireless_frames` (and therefore on `sync_events_expanded`). When
the field was parsed and stored in the column, the payload accessor returns null.

**Steps:**

Replace the JSONB extraction with a COALESCE that prefers the parsed column:

```sql
-- Before (in vec_update_transition_model windowed CTE):
coalesce(frame_subtype, payload->>'frame_subtype') as frame_subtype

-- The existing query already aliases a field named frame_subtype from
-- sync_events_expanded. Confirm the column is present in the view and
-- remove the payload fallback only when confirmed:
SELECT frame_subtype, payload->>'frame_subtype'
FROM sync_events_expanded
WHERE stream_name = 'wireless.audit'
  AND observed_at >= now() - interval '1 hour'
LIMIT 10;
```

If the column is consistently populated, simplify to:

```sql
COALESCE(
  NULLIF(frame_subtype, ''),
  NULLIF(payload->>'frame_subtype', '')
) AS frame_subtype
```

The same fix applies to `vec_build_frame_sequences` (the renamed function from Fix 1):

```sql
-- In the prepared CTE of vec_build_frame_sequences:
COALESCE(
  NULLIF(frame_subtype, ''),
  NULLIF(payload->>'frame_subtype', '')
) AS frame_subtype
```

Add a diagnostic query to confirm population before relying on the model:

```sql
SELECT COUNT(*) FROM vec_transition_model;
-- If 0 after a manual SELECT vec_update_transition_model():
-- run the column audit above to confirm the root cause.
```

---

### Fix 4 — Null-safe location_id / sensor_id in all vec_ builder functions

**Files:** `sql/postgres.sql`, `services/vec-worker/src/text_builder.rs`

**Problem:** When `location_id` or `sensor_id` is null in the source row, it propagates
through `EmbeddingInput` into `CompleteBatchRow` and then into `vec_embeddings` and
`vec_alerts`. This is mostly harmless for storage but breaks alert cooldown deduplication
when the `WHERE ... AND sensor_id = $sensor_id` predicate is used with nulls.

**SQL side — `vec_build_behaviour_snapshots`:** already uses `min(sensor_id) FILTER
(WHERE sensor_id IS NOT NULL)`, so this is handled. No change needed there.

**SQL side — `vec_build_frame_sequences` (renamed Fix 1 function):** the `prepared` CTE
uses bare `sensor_id` and `location_id` fields. Add explicit null-filter coalescing:

```sql
-- In the prepared CTE grouping:
MIN(NULLIF(COALESCE(sensor_id, payload->>'sensor_id'), '')) AS sensor_id,
MIN(NULLIF(COALESCE(location_id, payload->>'location_id'), '')) AS location_id,
```

**Rust side — `text_builder.rs`:** `frame_sequence_row_to_input` skips the sensor/location
lines when values are `None` — this is correct behavior. No change needed.

**Alert cooldown queries — `alerts.rs`:** the `IS NOT DISTINCT FROM` operator already
handles null equality correctly in `check_near_duplicates`. No change needed there.

**Verify the null volume before and after:**

```sql
SELECT
  COUNT(*) FILTER (WHERE sensor_id IS NULL)     AS null_sensor,
  COUNT(*) FILTER (WHERE location_id IS NULL)   AS null_location,
  COUNT(*)                                       AS total
FROM vec_frame_sequences;
```

---

### Fix 5 — Deduplicate LATERAL endpoint expansion in `build_infrastructure_subgraphs_batch`

**Files:** `sql/postgres.sql`

**Problem:** The LATERAL in `build_infrastructure_subgraphs_batch` emits one row per
matching endpoint per edge. When a `bssid` appears as both `node_a` and `node_b` in
different edges, the same edge struct is added twice to the grouped HashMap, doubling
client/vendor counts.

**Steps:**

Replace the LATERAL with a simpler `WHERE` clause that uses `DISTINCT ON` to emit each
edge once per matching query key:

```sql
-- Replace the existing LATERAL block with:
SELECT DISTINCT ON (
    LEAST(node_a, node_b),
    GREATEST(node_a, node_b),
    edge_type,
    endpoint
  )
  endpoint AS query_key,
  node_a, node_a_type,
  node_b, node_b_type,
  edge_type, weight::float8, last_seen
FROM vec_infrastructure_graph
CROSS JOIN LATERAL (
  VALUES
    (CASE WHEN node_a = ANY($1::text[]) THEN node_a END),
    (CASE WHEN node_b = ANY($1::text[]) THEN node_b END)
) AS endpoints(endpoint)
WHERE endpoint IS NOT NULL
ORDER BY
  LEAST(node_a, node_b),
  GREATEST(node_a, node_b),
  edge_type,
  endpoint,
  last_seen DESC;
```

This guarantees one row per (edge, matching-key) combination, eliminating the
inflation.

---

### Fix 6 — Register `frame_sequence` HNSW index for `vec_similarity_pairs` matching

**Files:** `sql/postgres.sql`

**Problem:** `vec_similarity_pairs` has a `sequence_sequence` pair kind in its check
constraint but `vec_materialize_similarity_pairs` never generates `sequence_sequence`
pairs. Without HNSW-driven similarity search for frame sequences, the MAC-rotation and
attack-pattern detection tracks (Track 2.2) cannot function.

**Steps:**

The HNSW index `vec_embeddings_frame_sequence_hnsw_768_idx` already exists in the
schema. Add a `sequence_sequence` block to `vec_materialize_similarity_pairs` mirroring
the `event_event` block:

```sql
-- Inside vec_materialize_similarity_pairs, after the behaviour_window block:
WITH seq_candidates AS (
  SELECT
    LEAST(e1.embedding_id, neighbor.embedding_id)    AS left_embedding_id,
    GREATEST(e1.embedding_id, neighbor.embedding_id) AS right_embedding_id,
    MIN(neighbor.cosine_distance)                    AS cosine_distance
  FROM vec_embeddings e1
  JOIN LATERAL (
    SELECT
      e2.embedding_id,
      (e2.embedding::vector(768) <=> e1.embedding::vector(768)) AS cosine_distance
    FROM vec_embeddings e2
    WHERE e2.embedding_kind       = 'frame_sequence'
      AND e2.embedding_model      = p_model
      AND e2.embedding_dimensions = 768
      AND e2.embedding_id        <> e1.embedding_id
    ORDER BY e2.embedding::vector(768) <=> e1.embedding::vector(768)
    LIMIT GREATEST(p_top_k, 1)
  ) neighbor ON TRUE
  WHERE e1.embedding_kind       = 'frame_sequence'
    AND e1.embedding_model      = p_model
    AND e1.embedding_dimensions = 768
    AND neighbor.cosine_distance <= 0.10  -- tunable threshold
  GROUP BY
    LEAST(e1.embedding_id, neighbor.embedding_id),
    GREATEST(e1.embedding_id, neighbor.embedding_id)
)
INSERT INTO vec_similarity_pairs (
  pair_kind, embedding_model, embedding_kind,
  left_embedding_id, right_embedding_id,
  left_source_table, left_source_key, left_source_mac,
  left_sensor_id, left_location_id, left_observed_at,
  right_source_table, right_source_key, right_source_mac,
  right_sensor_id, right_location_id, right_observed_at,
  cosine_distance, cosine_similarity, rank, evidence,
  computed_at, created_at, updated_at
)
SELECT
  'sequence_sequence', p_model, 'frame_sequence',
  c.left_embedding_id, c.right_embedding_id,
  le.source_table, le.source_key, le.source_mac,
  le.source_sensor_id, le.source_location_id, le.source_observed_at,
  re.source_table, re.source_key, re.source_mac,
  re.source_sensor_id, re.source_location_id, re.source_observed_at,
  c.cosine_distance,
  1 - c.cosine_distance,
  1,
  jsonb_build_object('detector', 'similar_frame_sequence', 'threshold', 0.10),
  now(), now(), now()
FROM seq_candidates c
JOIN vec_embeddings le ON le.embedding_id = c.left_embedding_id
JOIN vec_embeddings re ON re.embedding_id = c.right_embedding_id
ON CONFLICT (pair_kind, embedding_model, embedding_kind,
             left_embedding_id, right_embedding_id)
DO UPDATE SET
  cosine_distance  = EXCLUDED.cosine_distance,
  cosine_similarity = EXCLUDED.cosine_similarity,
  computed_at      = now(),
  updated_at       = now();
```

---

## Verification Queries

Run these in order after deploying fixes. All should return non-zero row counts
within 10–15 minutes of cron execution.

```sql
-- 1. Confirm vec_build_frame_sequences is correctly named
SELECT proname, pronargs
FROM pg_proc
WHERE proname IN ('vec_build_frame_sequences', 'vec_build_baseline_profiles');

-- 2. Confirm cron jobs are registered
SELECT jobname, schedule, command
FROM cron.job
WHERE jobname LIKE 'vec-%'
ORDER BY jobname;

-- 3. Manually trigger frame sequence build and inspect
SELECT vec_build_frame_sequences();
SELECT COUNT(*), MIN(window_start), MAX(window_end) FROM vec_frame_sequences;

-- 4. Manually trigger transition model update and inspect
SELECT vec_update_transition_model();
SELECT COUNT(*) FROM vec_transition_model;
SELECT SUM(count) AS total_bigrams FROM vec_transition_model;

-- 5. Confirm frame_sequence jobs are being enqueued
SELECT vec_enqueue_embedding_jobs();
SELECT embedding_kind, COUNT(*), MIN(due_at), MAX(due_at)
FROM vec_embedding_jobs
GROUP BY embedding_kind
ORDER BY embedding_kind;

-- 6. Confirm null rate in frame sequences after Fix 4
SELECT
  COUNT(*) FILTER (WHERE sensor_id IS NULL)   AS null_sensor,
  COUNT(*) FILTER (WHERE location_id IS NULL) AS null_location,
  COUNT(*) AS total
FROM vec_frame_sequences;

-- 7. Confirm vec_score_sequence returns meaningful values after model population
SELECT vec_score_sequence(ARRAY['BEACON', 'AUTH', 'ASSOC_REQ', 'EAPOL', 'DATA_QOS']);
-- Expect a negative log-prob, e.g. -5.2 to -12.0 for a common sequence

-- 8. Spot-check infrastructure graph ego-graph for duplicate inflation
SELECT node_a, COUNT(*) AS edge_count
FROM vec_infrastructure_graph
WHERE node_a_type = 'bssid'
GROUP BY node_a
ORDER BY edge_count DESC
LIMIT 5;
-- Compare with what build_ego_graph_input reports for the same bssid
```

---

## Deployment Order

| Step | Action | Risk |
|------|--------|------|
| 1 | Run verification queries above to establish baseline counts | None |
| 2 | Apply Fix 3 (column vs payload COALESCE) — safest, additive only | Low |
| 3 | Apply Fix 1 (rename function + add cron) — requires DROP of mislabeled overload | Medium — brief window where frame sequences not built |
| 4 | Apply Fix 2 (add frame_sequence to enqueue function) | Low |
| 5 | Apply Fix 4 (null-safe location/sensor in frame sequences) | Low |
| 6 | Apply Fix 5 (deduplicate LATERAL) | Low |
| 7 | Apply Fix 6 (sequence_sequence similarity pairs) | Low |
| 8 | `SELECT vec_build_frame_sequences()` manually to backfill | None |
| 9 | `SELECT vec_update_transition_model()` manually to bootstrap | None |
| 10 | `SELECT vec_enqueue_embedding_jobs()` manually to queue backfill | None |
| 11 | Run verification queries again — confirm all counts non-zero | None |
| 12 | Monitor `batch timing` logs in vec-worker for `frame_sequence` jobs appearing | None |

---

## One-liner Backfill After Deploy

```sql
-- Run once after all fixes are applied to bootstrap the pipeline end-to-end
DO $$
BEGIN
  PERFORM vec_build_frame_sequences(NOW() - INTERVAL '7 days', NOW());
  PERFORM vec_update_transition_model();
  PERFORM vec_build_baseline_profiles(NOW() - INTERVAL '7 days', NOW());
  PERFORM vec_enqueue_embedding_jobs();
  RAISE NOTICE 'Backfill complete. Check vec_frame_sequences, vec_transition_model, and vec_embedding_jobs.';
END;
$$;
```