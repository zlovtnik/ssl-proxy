defmodule TrafficAudit.Io.Ja3 do
  @moduledoc """
  Extracts JA3 fingerprints from a pcap via tshark (`-z ja3,tree`).

  Returns the unique 32-hex JA3 hashes found in the output. Diffing them
  against a browser reference table to produce an L4 match confidence is a
  follow-up; `TrafficAudit.Domain.FlowStats.composite/3` accepts either the
  raw list (scores 0.0) or a pre-computed float.

  Degradation: Wireshark 4.x (Debian bookworm) removed the `ja3,tree`
  statistics argument, so the runtime image intentionally omits tshark. When
  tshark is missing or reports `Invalid -z argument`, `extract/1` degrades to
  `{:ok, []}` — an L4 weight of 0.0 means this cannot affect transport
  selection. Any other tshark failure (non-zero exit, unexpected output) still
  errors.
  """

  require Logger

  alias TrafficAudit.Io.Shell

  @spec extract(binary()) :: {:ok, [String.t()]} | {:error, term()}
  def extract(pcap) do
    case Shell.run_with_input("tshark", ["-z", "ja3,tree"], pcap, "-r") do
      {:ok, out} ->
        {:ok, parse(out)}

      {:error, {:command_not_found, "tshark"}} ->
        degrade()

      {:error, {:command_failed, _, 1, err}} when is_binary(err) ->
        if String.contains?(err, "Invalid -z argument") do
          degrade()
        else
          {:error, {:command_failed, "tshark", 1, err}}
        end

      {:error, _} = err ->
        err
    end
  end

  defp degrade do
    Logger.warning(
      "tshark JA3 support unavailable (missing binary or Wireshark 4.x without ja3,tree); returning no JA3 fingerprints"
    )

    {:ok, []}
  end

  @doc false
  @spec parse(binary()) :: [String.t()]
  def parse(out) when is_binary(out) do
    Regex.scan(~r/\b[0-9a-f]{32}\b/, out)
    |> List.flatten()
    |> Enum.uniq()
  end
end
