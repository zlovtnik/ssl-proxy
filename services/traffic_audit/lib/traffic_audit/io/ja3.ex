defmodule TrafficAudit.Io.Ja3 do
  @moduledoc """
  Extracts JA3 fingerprints from a pcap via tshark raw-field extraction.

  Runs `tshark -Y 'tls.handshake.type==1' -T fields ...` — one output line
  per ClientHello, comma-separated fields, dash-joined repeats within a field
  (`-E occurrence=a -E aggregator=-`), exactly JA3's internal field format.
  Each line is reduced to its 32-hex JA3 MD5 by
  `TrafficAudit.Domain.Ja3`, a version-proof hash that does not depend on the
  `-z ja3,tree` statistics argument Wireshark 4.x removed.

  Degradation: only a genuinely absent tshark degrades to `{:ok, []}` (no
  fingerprints, L4 weight 0.0). Any tshark run that fails still errors.
  """

  require Logger

  alias TrafficAudit.Domain.Ja3
  alias TrafficAudit.Io.Shell

  @tshark_args [
    "-Y",
    "tls.handshake.type==1",
    "-T",
    "fields",
    "-e",
    "tls.handshake.version",
    "-e",
    "tls.handshake.ciphersuite",
    "-e",
    "tls.handshake.extensions.type",
    "-e",
    "tls.handshake.extensions_supported_groups",
    "-e",
    "tls.handshake.extensions_ec_point_formats",
    "-E",
    "separator=,",
    "-E",
    "occurrence=a",
    "-E",
    "aggregator=-"
  ]

  @spec extract(binary(), keyword()) :: {:ok, [String.t()]} | {:error, term()}
  def extract(pcap, opts \\ []) do
    case Shell.run_with_input("tshark", @tshark_args, pcap, "-r", opts) do
      {:ok, out} ->
        {:ok, parse(out)}

      {:error, {:command_not_found, "tshark"}} ->
        degrade()

      {:error, _} = err ->
        err
    end
  end

  defp degrade do
    Logger.warning("tshark unavailable; returning no JA3 fingerprints (L4 weight is 0.0)")

    {:ok, []}
  end

  @doc false
  @spec parse(binary()) :: [String.t()]
  def parse(out) when is_binary(out) do
    out
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&Ja3.hash/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end
end
