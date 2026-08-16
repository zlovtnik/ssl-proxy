defmodule TrafficAudit.Domain.Generators do
  @moduledoc """
  Test-only StreamData generators for pure-domain property tests.

  Kept under `test/support/` because `ExUnitProperties`/`StreamData` are
  test-only deps (see `elixirc_paths` in `mix.exs`).
  """
  use ExUnitProperties

  alias TrafficAudit.Domain.Types.Packet

  @doc "A single packet with a non-negative size, a direction, and a timestamp."
  @spec packet() :: StreamData.t()
  def packet do
    StreamData.map(
      StreamData.tuple({
        StreamData.integer(0..1500),
        StreamData.one_of([:in, :in, :out]),
        StreamData.float(min: 0.0, max: 10.0, max_digits: 6)
      }),
      fn {size, direction, ts} -> %Packet{size: size, direction: direction, ts: ts} end
    )
  end

  @doc "A bounded, timestamp-sorted list of packets (non-empty)."
  @spec packets() :: StreamData.t()
  def packets do
    StreamData.list_of(packet(), min_length: 1, max_length: 40)
    |> StreamData.map(&Enum.sort_by(&1, fn %Packet{ts: ts} -> ts end))
  end
end
