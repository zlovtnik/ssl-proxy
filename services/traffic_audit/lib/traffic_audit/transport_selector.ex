defmodule TrafficAudit.TransportSelector do
  @moduledoc """
  Scores every candidate transport and picks the lowest composite score.

  Selection policy (confirmed):
    - any candidate pipeline failure fails the whole selection — an unscored
      transport means the winner cannot be certified as best;
    - among candidates passing the hard L3 gate (worst-of size/timing JS
      divergence <= 0.20), the lowest `composite_score` wins;
    - if nothing passes the gate, the selection errors.
  """

  alias TrafficAudit.Pipeline

  @threshold 0.20

  # Per-transport weight rows, each summing to 1.0. Only `tls_fronted`
  # produces a TLS ClientHello, so only it is scored against L4; obfs4 and
  # wireguard move that share onto L2/L3 instead of scoring a layer they
  # cannot produce.
  @weights_by_transport %{
    tls_fronted: [l1: 0.15, l2: 0.20, l3_size: 0.25, l3_timing: 0.25, l4: 0.15],
    obfs4: [l1: 0.15, l2: 0.25, l3_size: 0.30, l3_timing: 0.30, l4: 0.0],
    wireguard: [l1: 0.15, l2: 0.25, l3_size: 0.30, l3_timing: 0.30, l4: 0.0]
  }

  @doc """
  Candidate transports the gate audits each commit.
  """
  @spec transports() :: [atom()]
  def transports, do: [:obfs4, :wireguard, :tls_fronted]

  @doc """
  Runs the pipeline for every candidate and returns the winner map (see
  `TrafficAudit.Pipeline.score_transport/2`) or `{:error, reason}`.
  """
  @spec select_best([atom()], keyword()) :: {:ok, map()} | {:error, term()}
  def select_best(transports, opts \\ []) do
    results =
      Enum.map(transports, fn t ->
        {t, Pipeline.score_transport(t, put_transport_weights(t, opts))}
      end)

    with {:ok, oks} <- all_succeeded(results) do
      pick_winner(oks)
    end
  end

  defp all_succeeded(results) do
    case Enum.split_with(results, fn {_t, r} -> match?({:ok, _}, r) end) do
      {oks, []} -> {:ok, Enum.map(oks, fn {_t, {:ok, s}} -> s end)}
      {_oks, failures} -> {:error, {:some_transports_failed, failures}}
    end
  end

  defp pick_winner([]), do: {:error, :no_passing_transport}

  defp pick_winner(oks) do
    case Enum.filter(oks, &passes_gate?/1) do
      [] -> {:error, :no_passing_transport}
      passing -> {:ok, Enum.min_by(passing, & &1.composite_score)}
    end
  end

  defp passes_gate?(score) do
    flow = score.l3_flow
    max(flow.l3_size_divergence, flow.l3_timing_divergence) <= @threshold
  end

  defp put_transport_weights(transport, opts) do
    case Map.fetch(@weights_by_transport, transport) do
      {:ok, weights} -> Keyword.put(opts, :weights, weights)
      :error -> opts
    end
  end
end
