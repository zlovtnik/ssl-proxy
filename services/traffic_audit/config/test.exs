import Config

# Persistence is log-only by default; the Repo is never started from the
# supervision tree in tests (see TrafficAudit.Application).
config :traffic_audit, :persistence, :log

config :traffic_audit, TrafficAudit.Repo,
  pool: Ecto.Adapters.SQL.Sandbox,
  ownership_timeout: 5_000
