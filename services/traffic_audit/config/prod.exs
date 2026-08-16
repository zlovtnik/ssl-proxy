import Config

config :traffic_audit, TrafficAudit.Repo,
  # Production reads TLS credentials from the Kubernetes secret injected by the
  # schema executor; DSN is assembled by config/runtime.exs from env vars.
  pool_size: 10
