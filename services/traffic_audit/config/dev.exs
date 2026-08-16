import Config

config :traffic_audit, TrafficAudit.Repo,
  # Devs can point this at a local TiDB; no credentials are committed.
  url:
    System.get_env("TRAFFIC_AUDIT_TIDB_DSN") ||
      "mysql://traffic_audit:pw@127.0.0.1:4000/traffic_audit",
  pool_size: 5
