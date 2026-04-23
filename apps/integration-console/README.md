# Integration Console

Rails management interface for the wireless sensor sync plane.

## Local configuration

- `DATABASE_URL` stores console-owned tables. In the compose stack this defaults to the existing `sync` Postgres database.
- `SYNC_DATABASE_URL` reads existing sync-plane tables and views. Defaults to `DATABASE_URL`.
- `SYNC_NATS_URL` points at NATS.
- `INTEGRATION_CONSOLE_REDIS_URL` backs ActionCable broadcasts.
- `INTEGRATION_CONSOLE_FULL_MACS=true` allows full MAC display in audit logs; otherwise MACs are masked.
- Compose development stacks must set `ADMIN_API_KEY` explicitly before starting admin endpoints.

## Commands

```sh
bundle install
bin/rails db:prepare
bin/rails test
bin/rails server
```

Run the worker with:

```sh
bin/rails runner 'Nats::Subscriber.new.run_forever'
```

Run the heartbeat monitor periodically with:

```sh
bin/rails runner 'SensorHeartbeatMonitor.new.call'
```
