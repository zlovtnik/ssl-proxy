defmodule TrafficAudit.Pipeline do
  @moduledoc """
  Scores one transport's traffic fingerprint. Reads top to bottom: capture,
  DPI-scan, JA3-extract, then pure flow-stats scoring.

  `with` short-circuits on the first `{:error, _}` exactly like an effect
  interpreter's bind would — using syntax every Elixir dev already knows.

  Each IO step is injectable via `:capture_fn`, `:dpi_fn`, and `:ja3_fn` opts
  for tests; production calls hit `TrafficAudit.Io.*`.
  """

  alias TrafficAudit.{Domain, Io}

  @scoring_opts [:reference, :threshold, :weights, :commit_sha, :l1, :l2, :l4_ja3_match]

  @spec score_transport(atom(), keyword()) :: {:ok, map()} | {:error, term()}
  def score_transport(transport, opts \\ []) do
    with {:ok, pcap} <- capture(transport, opts),
         {:ok, dpi} <- dpi(pcap, opts),
         {:ok, ja3} <- ja3(pcap, opts) do
      scoring_opts =
        opts
        |> Keyword.take(@scoring_opts)
        |> Keyword.put_new(:l2, dpi)
        |> Keyword.put_new(:l4_ja3_match, ja3)

      flow = Domain.FlowStats.score(pcap, transport, scoring_opts)

      {:ok,
       %{
         transport: transport,
         l2_dpi: dpi,
         l3_flow: flow,
         l4_ja3: ja3,
         composite_score: flow.composite
       }}
    end
  end

  defp capture(transport, opts) do
    case Keyword.get(opts, :capture_fn) do
      nil -> Io.Capture.run(transport, opts)
      fun -> fun.(transport, opts)
    end
  end

  defp dpi(pcap, opts) do
    case Keyword.get(opts, :dpi_fn) do
      nil -> Io.Dpi.scan(pcap)
      fun -> fun.(pcap)
    end
  end

  defp ja3(pcap, opts) do
    case Keyword.get(opts, :ja3_fn) do
      nil -> Io.Ja3.extract(pcap)
      fun -> fun.(pcap)
    end
  end
end
