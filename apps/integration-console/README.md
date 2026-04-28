# Integration Console

Rails management interface for the wireless sensor sync plane.

## Local configuration

- `DATABASE_URL` stores console-owned tables. In the compose stack this defaults to the existing `sync` Postgres database.
- `SYNC_DATABASE_URL` reads existing sync-plane tables and views. Defaults to `DATABASE_URL`.
- `SYNC_DB_POOL` controls the read-side sync database connection pool. Defaults to `RAILS_MAX_THREADS` or `5`.
- `SYNC_NATS_URL` points at NATS.
- `INTEGRATION_CONSOLE_REDIS_URL` backs ActionCable broadcasts.
- `INTEGRATION_CONSOLE_FULL_MACS=true` allows full MAC display in audit logs; otherwise MACs are masked.
- `HEATMAP_REFRESH_INTERVAL_SECONDS` controls the materialized heatmap refresh worker interval. Defaults to `300` seconds.
- Compose development stacks must set `ADMIN_API_KEY` explicitly before starting admin endpoints.

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
