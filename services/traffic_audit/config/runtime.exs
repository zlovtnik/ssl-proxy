import Config

# Runtime-only configuration: read TiDB credentials from the environment.
# Mirrors the cross-service TIDB_* env-var family (see services/AGENTS.md).
# The 5th isolated domain is `traffic_audit`; the account is provisioned by the
# tidb-schema-executor bootstrap + least-privilege grant fixture in
# sql/tidb/traffic_audit/grants/.

repo_config = [
  username: System.get_env("TRAFFIC_AUDIT_TIDB_USER"),
  password: System.get_env("TRAFFIC_AUDIT_TIDB_PASSWORD"),
  hostname: System.get_env("TRAFFIC_AUDIT_TIDB_HOST") || "127.0.0.1",
  port: (System.get_env("TRAFFIC_AUDIT_TIDB_PORT") || "4000") |> String.to_integer(),
  database: System.get_env("TRAFFIC_AUDIT_TIDB_DATABASE") || "traffic_audit",
  pool_size: (System.get_env("TRAFFIC_AUDIT_TIDB_POOL_SIZE") || "10") |> String.to_integer(),
  connect_timeout: 5_000,
  timeout: 15_000,
  ownership_timeout: 15_000,
  ssl: true,
  ssl_opts:
    [
      server_name_indication: System.get_env("TRAFFIC_AUDIT_TIDB_TLS_SERVER_NAME"),
      verify: :verify_peer,
      depth: 2
    ] ++
      case System.get_env("TRAFFIC_AUDIT_TIDB_TLS_CA_FILE") do
        nil -> [cacerts: :public_key.cacerts_get()]
        ca_file -> [cacertfile: ca_file]
      end,
  socket_options: [:binary],
  prepare: :unnamed
]

config :traffic_audit, TrafficAudit.Repo, repo_config
