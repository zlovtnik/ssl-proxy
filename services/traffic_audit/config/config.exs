import Config

# Static, non-runtime configuration.
import_config "#{config_env()}.exs"

config :traffic_audit, :capture,
  default_duration_s: 30,
  binary: System.get_env("TRAFFIC_AUDIT_CAPTURE_BIN") || "tcpdump",
  interface: System.get_env("TRAFFIC_AUDIT_CAPTURE_IFACE") || "any",
  mode: System.get_env("TRAFFIC_AUDIT_CAPTURE_MODE") || "live",
  # Live capture requires NET_RAW / NET_ADMIN on the container. The CI runner
  # must grant these Linux capabilities to the job container.
  require_caps: ["NET_RAW", "NET_ADMIN"]
