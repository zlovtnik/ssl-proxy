# Atheros Search degraded mode

Use this runbook when an Atheros Search alert fires, when a search answers
without semantic ranking, or when the wireless feed looks behind. Degraded mode
is a designed state: the API keeps serving, and the failure is reported through
stable fields instead of a crash.

Read-only cluster inspection is allowed here. Everything that changes desired
state belongs in a reviewed Git change under `cyber-stack/`, not in a terminal.

## What degraded mode means

- `/readyz` stays green on purpose. The embedding backend is not a readiness
  dependency, so a llama.cpp outage cannot pull the pod from rotation while
  keyword search, graph, inventory and suggest still work.
- `/v1/search` and `/v1/search/stream` keep answering. When the dense leg
  cannot run, the response carries `mode_used: SEARCH_MODE_SPARSE`,
  `fallback_reason`, `fallback_code` and, when the backend named a retry time,
  `fallback_retry_at`.
- A dense-only request cannot degrade. It returns HTTP 503 with the JSON body
  `{"error": "...", "code": "..."}` and a `Retry-After` header when a retry time
  is known. The gRPC transport reports the same failure as
  `codes.Unavailable`.
- `/v1/etl/health` carries the live view: `query_semantic`, `worker_semantic`
  and `wireless_projection` are merged at read time over the cached database
  snapshot, so they never lag behind the 30-second snapshot cache.

## Fallback codes

`fallback_code` is stable. `fallback_reason` is a safe static sentence that
never carries raw backend, SQL or circuit text.

| Code | Meaning | First action |
| --- | --- | --- |
| `embedding_backend_unavailable` | The backend refused, timed out, or answered 429/5xx. | Check [semantic backend unavailable](#semantic-backend-unavailable). |
| `embedding_capacity_exhausted` | The call never left the process: every permitted backend slot was busy until the search deadline. | Check [embedding queue not draining](#embedding-queue-not-draining) and raise capacity only after reading the trade-off below. |
| `embedding_invalid_response` | The backend answered, but the vectors were missing, the wrong count, or the wrong width. | Confirm the model and dimension settings match between the backend and `ATHSEARCH_EMBEDDING_MODEL`. |
| `no_embedding_coverage` | The dense leg ran and returned nothing because the requested kind has zero indexed vectors. | Check [embedding queue not draining](#embedding-queue-not-draining). |
| `dense_query_failed` | The dense vector SQL failed even though embedding succeeded. | Treat as a PostgreSQL incident; the sparse leg is still answering. |

## Metrics

All series come from the `ssl-proxy-atheros-search` job.

| Series | Reads as |
| --- | --- |
| `athsearch_embedding_backend_available{lane}` | 1 when the tokenizer preflight is compatible and that lane's circuit is not open. |
| `athsearch_embedding_circuit_state{lane,state}` | Exactly one of `closed`, `open`, `half_open` is 1 per lane. |
| `athsearch_embedding_limiter_in_use{lane}` and `..._capacity{lane}` | Slots held versus the cap. Workers are capped below the total so interactive queries always find an idle slot. |
| `athsearch_embedding_limiter_wait_seconds{lane}` | Histogram of queueing time for a backend slot. |
| `athsearch_embedding_preflight_state{state}` | Exactly one of `pending`, `compatible`, `incompatible`, `disabled`. |
| `athsearch_embedding_jobs{status}` | Queue counters from `embedding_jobs`. |
| `athsearch_embedding_oldest_pending_age_seconds` | Age of the oldest pending or leased job; 0 when the queue is empty. |
| `athsearch_embedding_active_workers` | Workers with a heartbeat inside the freshness window. |
| `athsearch_searchable_wireless_events` | Indexed wireless events in the last 24 hours. |
| `athsearch_wireless_newest_observation_seconds` | Unix time of the newest indexed observation; 0 when nothing has ever been indexed. |

## Semantic backend unavailable

Symptoms: `AtherosSearchSemanticBackendUnavailable` is firing, `query_semantic`
reporting `incompatible` or an `open` circuit, and searches reporting
`embedding_backend_unavailable`.

1. Confirm the pod and its logs:
   ```bash
   kubectl -n ssl-proxy get pods -l app.kubernetes.io/name=ssl-proxy-atheros-search
   kubectl -n ssl-proxy logs deploy/ssl-proxy-atheros-search --tail=200
   ```
2. Read `query_semantic` from `/v1/etl/health`. `preflight: incompatible` means
   the tokenizer round trip is failing; `circuit_state: open` means real query
   traffic has been failing for at least three consecutive attempts.
3. Verify the backend configured by `ATHSEARCH_EMBEDDING_BACKEND` answers
   `/tokenize` and `/detokenize` with the configured model. The preflight
   re-checks every minute while healthy and backs off to a minute while not.
4. Keyword search is unaffected. Do not restart the pod to clear a circuit: the
   breaker is per lane and per process, and it re-opens on the same evidence.

The interactive lane and the worker lane keep separate breakers on purpose, so a
hot bulk backlog cannot open the breaker that guards interactive search. Only
backend-attributable failures count. Caller cancellation, shutdown,
capacity-wait cancellation, oversized inputs and request-validation errors are
neutral.

## Embedding workers not running

Symptom: `AtherosSearchEmbeddingQueueUnattended` is firing.

1. Check whether the pool is enabled: `ATHSEARCH_WORKER_ENABLED` must be `true`.
2. Read `worker_semantic` from `/v1/etl/health`. While the tokenizer preflight is
   not compatible, workers deliberately skip the claim transaction so no attempt
   is consumed. The gate is checked before the transaction opens.
3. Check heartbeats: `athsearch_embedding_active_workers` is 0 and the `workers`
   array in `/v1/etl/health` is empty when no worker has reported in five
   minutes.
4. Confirm `embedding_dependency` in the same response. `waiting_for_worker`
   with pending jobs and no heartbeats matches this alert; `healthy` means the
   queue is already drained.

## Embedding queue not draining

Symptoms: `AtherosSearchEmbeddingQueueAging` or
`AtherosSearchEmbeddingQueueCritical`, plus
`no_embedding_coverage` fallbacks as coverage stops improving.

1. Read `embedding_dependency`, `embedding_pending`, `embedding_failed` and
   `oldest_embedding_job_at` from `/v1/etl/health`.
2. `blocked` means failed jobs exist. Inspect them before resetting anything:
   ```bash
   go run ./cmd/embedding-job-repair -action=status
   ```
   Run that from `apps/integration-console/atheros-search`.
3. `waiting_for_worker` with an available backend points at
   [embedding workers not running](#embedding-workers-not-running).
4. `backlog` with an open worker circuit means jobs are being deferred without
   consuming attempts. That is the intended behavior while the backend is down,
   and it resolves itself once the breaker closes.
5. Capacity trade-off: `ATHSEARCH_EMBEDDING_REQUEST_CONCURRENCY` is the global
   slot total and `ATHSEARCH_EMBEDDING_QUERY_RESERVED_SLOTS` is how many of
   those slots bulk workers may never take. Raising the total shortens bulk
   latency but lets workers crowd the backend more before interactive queries
   queue; raising the reservation protects interactive latency at the cost of
   bulk throughput. Change both through the production Kustomize patch, never
   in place.

## Wireless feed stale

Symptoms: `AtherosSearchWirelessFeedStale` or
`AtherosSearchWirelessFeedCritical`, `wireless_projection` reading `stale` or
`critical`.

`wireless_projection` is derived from the newest indexed observation:
`fresh` within 30 minutes, `stale` within 2 hours, `critical` beyond that, and
`unknown` when nothing has ever been indexed. A metric of 0 also fires the
critical alert, which is correct for an index that has never been written.

1. Read `wireless_last_observed_at` and `wireless_events_24h` from
   `/v1/etl/health`.
2. If `ingest_pending` or `ingest_failed` is non-zero, the problem is upstream
   of search. Hand it to the coordinator incident flow in the
   [operations runbook](../runbook.md).
3. If ingest looks clean but nothing is indexed, check `embedding_dependency`
   and the wireless ingest path rather than search itself.
4. Search is the read side. Do not write to the wireless tables to clear this
   alert.

## Recovery

Degraded mode ends when the underlying state changes; there is no switch to
flip. Expect, in order:

1. `athsearch_embedding_preflight_state{state="compatible"}` returns to 1.
2. `athsearch_embedding_backend_available{lane="interactive"}` returns to 1
   after the interactive breaker closes, within its 10-second to 2-minute
   reopen ladder.
3. The worker lane follows, then `athsearch_embedding_oldest_pending_age_seconds`
   falls back toward 0 as deferred jobs drain.
4. `wireless_projection` returns to `fresh` once the feed catches up.

If a state does not recover, capture the `/v1/etl/health` body and the alert
expression that is still firing before changing anything.

## Related documents

- [Operations runbook](../runbook.md)
- [Observability architecture](../observability-architecture-jaeger.md)
- [Observability runbook](observability.md)
