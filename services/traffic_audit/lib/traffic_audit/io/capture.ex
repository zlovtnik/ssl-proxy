defmodule TrafficAudit.Io.Capture do
  @moduledoc """
  Runs tcpdump for a transport and returns raw pcap bytes.

  Two modes, selected per-call or via `TRAFFIC_AUDIT_CAPTURE_MODE`:

    - `"live"` (default) — `timeout -s INT <s> tcpdump -i <iface> -w -`.
      tcpdump's own `-G` requires a strftime pattern in the `-w` filename, so
      the duration is enforced by `timeout` instead. Exit 0 and 124 (the
      status GNU `timeout` reports after signalling the child) both mean the
      capture ran its full window.
    - `"fixture"` — reads `priv/fixtures/<transport>.pcap`, a checked-in
      deterministic capture used by unprivileged CI.

  Live capture requires NET_RAW/NET_ADMIN on the runner (never baked into the
  image).
  """

  @spec run(atom(), keyword()) :: {:ok, binary()} | {:error, term()}
  def run(transport, opts \\ []) do
    case Keyword.get(opts, :mode, System.get_env("TRAFFIC_AUDIT_CAPTURE_MODE") || "live") do
      "fixture" -> fixture(transport)
      _ -> live(transport, opts)
    end
  end

  # Note: escripts do not evaluate `config/config.exs`, so runtime knobs are
  # read from the environment (the config file mirrors the same defaults for
  # `mix run` contexts).
  defp live(transport, opts) do
    seconds = duration(opts)
    iface = interface_for(transport, opts)
    bin = Keyword.get(opts, :binary) || System.get_env("TRAFFIC_AUDIT_CAPTURE_BIN") || "tcpdump"

    args = ["-s", "INT", to_string(seconds), bin, "-i", iface, "-w", "-"]

    case System.cmd("timeout", args) do
      {pcap, code} when code in [0, 124] -> {:ok, pcap}
      {out, code} -> {:error, {:capture_failed, code, out}}
    end
  end

  defp fixture(transport) do
    path = fixture_path(transport)

    case File.read(path) do
      {:ok, pcap} -> {:ok, pcap}
      {:error, reason} -> {:error, {:fixture_missing, path, reason}}
    end
  end

  defp fixture_path(transport) do
    dir = System.get_env("TRAFFIC_AUDIT_FIXTURE_DIR") || Path.join(File.cwd!(), "priv/fixtures")
    Path.join(dir, "#{transport}.pcap")
  end

  defp interface_for(_transport, opts) do
    Keyword.get(opts, :interface) ||
      System.get_env("TRAFFIC_AUDIT_CAPTURE_INTERFACE") ||
      "any"
  end

  defp duration(opts) do
    case Keyword.get(opts, :duration) || System.get_env("TRAFFIC_AUDIT_CAPTURE_DURATION_S") do
      nil -> 30
      s when is_binary(s) -> String.to_integer(s)
      s when is_integer(s) -> s
    end
  end
end
