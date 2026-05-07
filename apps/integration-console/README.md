# Integration Console

Rails management interface for the wireless sensor sync plane.

## Local configuration

- `DATABASE_URL` stores console-owned tables. In the compose stack this defaults to the existing `sync` Postgres database.
- `SYNC_DATABASE_URL` reads existing sync-plane tables and views. Defaults to `DATABASE_URL`.
- `SYNC_DB_POOL` controls the read-side sync database connection pool. Defaults to `RAILS_MAX_THREADS` or `5`.
- `STATEMENT_TIMEOUT` controls sync database statement timeouts in milliseconds. Defaults to `8000`.
- `LOCK_TIMEOUT` controls sync database lock wait timeouts in milliseconds. Defaults to `2000`.
- `SYNC_NATS_URL` points at NATS.
- `INTEGRATION_CONSOLE_REDIS_URL` backs ActionCable broadcasts.
- `INTEGRATION_CONSOLE_CACHE_TTL_INVENTORY` controls inventory JSON fragment cache TTL. Defaults to `60` seconds.
- `INTEGRATION_CONSOLE_CACHE_TTL_AUDIT_RECENT` controls recent audit JSON cache TTL. Defaults to `10` seconds.
- `INTEGRATION_CONSOLE_CACHE_TTL_DASHBOARD` controls dashboard card cache TTL. Defaults to `15` seconds.
- `INTEGRATION_CONSOLE_FULL_MACS=true` allows full MAC display in audit logs; otherwise MACs are masked.
- `HEATMAP_REFRESH_INTERVAL_SECONDS` controls the materialized heatmap refresh worker interval. Defaults to `300` seconds.
- `MINIO_ENDPOINT` points at the S3-compatible export cache. In Compose this defaults to `http://minio:9000`.
- `MINIO_ACCESS_KEY_ID` and `MINIO_SECRET_ACCESS_KEY` authenticate to MinIO.
- `MINIO_BUCKET` stores cached CSV exports. Defaults to `integration-console-exports`.
- `ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY`, `ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY`,
  and `ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT` configure Rails encrypted
  attributes. Development and test use deterministic local defaults when these are
  unset; production-like environments must set all three explicitly.
- Compose development stacks must set `ADMIN_API_KEY` explicitly before starting admin endpoints.

The root Compose stack includes a MinIO service and one-shot `minio-init`
container that creates `MINIO_BUCKET`. Cached export objects are cleaned up by
the Rails app when export requests run; objects older than 1 hour are deleted.

## Commands

```sh
bundle install
bun install
bin/rails db:prepare
bun run build
bin/rails test
bin/rails server
```

For frontend HMR during development, run the Rails server and Vite server in
separate terminals:

```sh
bin/rails server
bun run dev
```

Or run both with a Procfile runner:

```sh
bin/dev
```

Run the worker with:

```sh
bin/rails runner 'Nats::Subscriber.new.run_forever'
```

Run the heartbeat monitor periodically with:

```sh
bin/rails runner 'SensorHeartbeatMonitor.new.call'
```

Refresh heatmap aggregates every 5 minutes in production-like deployments:

```sh
bin/rails runner 'WirelessHeatmap.refresh!'
```
