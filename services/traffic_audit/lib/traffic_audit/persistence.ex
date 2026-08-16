defmodule TrafficAudit.Persistence do
  @moduledoc """
  The single save call site for a scored audit — one function, swapped at one
  place, nothing else in the codebase knows which backend is active.

  Modes (config `:traffic_audit, :persistence`, default `:log`):

    - `:log` (Option C, default) — structured log line, no database. The CI
      gate decides the winner in-process and needs no read-back, so history
      persistence is deferred until the TiDB governance surface
      (`sql/tidb/traffic_audit/`, grants, schema-executor manifest) exists.
    - `:repo` (Option A, one flag away) — idempotent
      `(commit_sha, transport)` upsert via `TrafficAudit.Repo`, so
      at-least-once re-runs are deduped.
  """

  require Logger

  alias TrafficAudit.Repo
  alias TrafficAudit.Schemas.TransportScore

  @spec save(String.t(), map(), keyword()) :: {:ok, term()} | {:error, term()}
  def save(commit_sha, winner, opts \\ []) do
    case Keyword.get(opts, :mode, Application.get_env(:traffic_audit, :persistence, :log)) do
      :repo -> repo_save(commit_sha, winner)
      _ -> log_save(commit_sha, winner)
    end
  end

  defp log_save(commit_sha, winner) do
    Logger.info(
      "traffic_audit score recorded commit=#{String.slice(commit_sha, 0, 12)} " <>
        "transport=#{winner.transport} composite=#{winner.composite_score}"
    )

    {:ok, :recorded}
  end

  defp repo_save(commit_sha, winner) do
    score = %{winner.l3_flow | commit_sha: commit_sha}

    attrs =
      score
      |> TransportScore.to_attrs(commit_sha: commit_sha)
      |> Map.put(:selected, true)

    replace_cols =
      Enum.reject(TransportScore.__schema__(:fields), &(&1 in [:commit_sha, :transport]))

    case Repo.insert_all(TransportScore, [Map.from_struct(attrs)],
           on_conflict: {:replace, replace_cols},
           returning: false
         ) do
      {n, _} when n in [0, 1, 2] -> {:ok, attrs}
      other -> {:error, {:unexpected_insert_all, other}}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end
end
