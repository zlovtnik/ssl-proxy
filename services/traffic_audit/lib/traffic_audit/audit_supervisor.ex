defmodule TrafficAudit.AuditSupervisor do
  @moduledoc """
  Composition root — the one place that runs a full audit for a commit:
  score every candidate transport, pick the winner, persist it.
  """

  alias TrafficAudit.{Persistence, TransportSelector}

  @doc """
  Runs the per-commit transport audit.

  ## Options
    - `:transports` — candidates (default `TransportSelector.transports/0`)
    - `:capture_fn` / `:dpi_fn` / `:ja3_fn` — injected IO handlers for tests
      (see `TrafficAudit.Pipeline.score_transport/2`)
    - `:mode` — persistence mode override (see `TrafficAudit.Persistence`)

  Returns `{:ok, winner}` or `{:error, reason}`.
  """
  @spec run(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def run(commit_sha, opts \\ []) when is_binary(commit_sha) do
    transports = Keyword.get(opts, :transports, TransportSelector.transports())

    with {:ok, winner} <- TransportSelector.select_best(transports, Keyword.put_new(opts, :commit_sha, commit_sha)) do
      case Persistence.save(commit_sha, winner, opts) do
        {:error, reason} -> {:error, reason}
        _ -> {:ok, winner}
      end
    end
  end
end
