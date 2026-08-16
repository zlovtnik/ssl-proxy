defmodule TrafficAudit.Io.Dpi do
  @moduledoc """
  Runs ndpiReader against a pcap and returns the classification output.

  The result map carries the raw `ndpiReader` output. Deriving a single
  `:confidence` float from it is a follow-up; the composite scorer treats a
  missing `:confidence` as 0.0 (see `TrafficAudit.Domain.FlowStats.composite/3`).
  """

  alias TrafficAudit.Io.Shell

  @spec scan(binary()) :: {:ok, map()} | {:error, term()}
  def scan(pcap) do
    with {:ok, out} <- Shell.run_with_input("ndpiReader", [], pcap, "-i") do
      {:ok, %{raw: out}}
    end
  end
end
