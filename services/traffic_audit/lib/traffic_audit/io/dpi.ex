defmodule TrafficAudit.Io.Dpi do
  @moduledoc """
  Runs ndpiReader against a pcap and returns a structured classification
  summary.

  ndpiReader's banner and statistics block (merged stdout/stderr) are parsed by
  `TrafficAudit.Domain.DpiSummary` into the version, packet and flow counts,
  the per-protocol breakdown, and the classification confidence used as the L2
  score. The raw text is not carried into the result: it is large, volatile,
  and unneeded by consumers.
  """

  alias TrafficAudit.{Domain, Io}

  @spec scan(binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def scan(pcap, opts \\ []) do
    with {:ok, out} <- Io.Shell.run_with_input("ndpiReader", [], pcap, "-i", opts) do
      {:ok, Domain.DpiSummary.parse(out)}
    end
  end
end
