defmodule TrafficAudit.Schemas.TransportScore do
  @moduledoc """
  Ecto schema for the `transport_scores` TiDB table.

  Dormant under the default `:log` persistence mode: nothing starts
  `TrafficAudit.Repo` or writes rows until the `:repo` mode is enabled, which
  in turn waits for the canonical DDL (`sql/tidb/`, schema-executor manifest)
  to be provisioned. See `TrafficAudit.Persistence`.
  """

  use Ecto.Schema

  @table "transport_scores"
  @primary_key false

  def table, do: @table

  schema @table do
    field(:commit_sha, :string)
    field(:transport, :string)
    field(:l1_score, :decimal)
    field(:l2_score, :decimal)
    field(:l3_size_divergence, :decimal)
    field(:l3_timing_divergence, :decimal)
    field(:l4_ja3_match, :decimal)
    field(:composite_score, :decimal)
    field(:selected, :boolean, default: false)
    timestamps()
  end

  @doc """
  Builds the attrs map persisted by `TrafficAudit.Persistence` (repo mode)
  from a domain `Score`.

  `selected` defaults to `false`.
  """
  @spec to_attrs(TrafficAudit.Domain.Types.Score.t(), keyword()) :: map()
  def to_attrs(%TrafficAudit.Domain.Types.Score{} = score, opts \\ []) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    %{
      __struct__: __MODULE__,
      commit_sha: Keyword.get(opts, :commit_sha),
      transport: Atom.to_string(score.transport),
      l1_score: to_decimal(score.l1),
      l2_score: to_decimal(l2_confidence(score.l2)),
      l3_size_divergence: to_decimal(score.l3_size_divergence),
      l3_timing_divergence: to_decimal(score.l3_timing_divergence),
      l4_ja3_match: to_decimal(score.l4_ja3_match),
      composite_score: to_decimal(score.composite),
      selected: false,
      inserted_at: now,
      updated_at: now
    }
  end

  defp to_decimal(nil), do: nil
  defp to_decimal(n) when is_float(n), do: Decimal.from_float(n)
  defp to_decimal(%Decimal{} = d), do: d
  defp to_decimal(n) when is_number(n), do: Decimal.new(n)

  defp l2_confidence(nil), do: 0.0
  defp l2_confidence(%{confidence: c}), do: c
  defp l2_confidence(_), do: 0.0
end
