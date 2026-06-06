# atheros-search worker cut-over

`atheros-search` now includes the migrated embedding worker and alert sweep
subsystems that previously lived in `vec-worker`.

## Enable in deployment

Set these environment variables on the `atheros-search` deployment after the
Rust `vec-worker` process/container has been stopped:

```sh
ATHSEARCH_WORKER_ENABLED=true
ATHSEARCH_ALERT_ENABLED=true
```

The worker uses the existing `ATHSEARCH_POSTGRES_DSN`, embedding backend, model,
and dimensions. Optional worker tuning variables are documented in
`internal/config/config.go` and use the `ATHSEARCH_WORKER_` prefix.

## Monitor after cut-over

Monitor these signals for at least 24 hours before deleting the retired Rust
worker artifacts:

- `vec_worker_state` heartbeat for the configured `ATHSEARCH_WORKER_NAME`
- `athsearch_worker_jobs_completed_total`
- `athsearch_worker_jobs_failed_total`
- `athsearch_worker_jobs_permanent_total`
- `athsearch_worker_queue_depth`
- `athsearch_alerts_inserted_total`

## Cleanup gate

Only remove `services/vec-worker` and its image/cron documentation after the
24-hour stability window has passed with healthy heartbeats and a draining queue.
This repository does not contain production deployment manifests for the worker,
so registry cleanup and environment changes must be performed in the deployment
system that runs these services.
