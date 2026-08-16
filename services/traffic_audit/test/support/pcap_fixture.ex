defmodule TrafficAudit.Domain.PcapFixture do
  @moduledoc """
  Test-only deterministic libpcap builder (mirrors
  `scripts/generate_fixtures.exs`).

  Real bytes, no fabricated inputs at assertion time: tests build a pcap
  binary from a size list and an inter-packet-gap list, parse it with
  `TrafficAudit.Domain.Pcap`, and score the parsed packets.
  """

  @sizes_ref [
    0,
    0,
    64,
    64,
    64,
    128,
    128,
    256,
    256,
    256,
    256,
    512,
    512,
    512,
    512,
    512,
    512,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1408,
    1472,
    1472,
    1472,
    1472,
    1472
  ]
  @gaps_ref_ms [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    10,
    10,
    10,
    10,
    10,
    10,
    10,
    20,
    20,
    20,
    20,
    30,
    30,
    30,
    30,
    40,
    40,
    40,
    60,
    60,
    80,
    80
  ]

  @doc "Packet sizes matching the reference_https/0 size distribution."
  @spec reference_like_sizes() :: [non_neg_integer()]
  def reference_like_sizes, do: @sizes_ref

  @doc "Inter-packet gaps (ms) approximating the reference_https/0 timing distribution."
  @spec reference_like_gaps() :: [non_neg_integer()]
  def reference_like_gaps, do: @gaps_ref_ms

  @doc "A degenerate burst of full-size packets (fails the 0.20 gate)."
  @spec degenerate_sizes() :: [pos_integer()]
  def degenerate_sizes, do: List.duplicate(1408, 33)

  @spec degenerate_gaps() :: [non_neg_integer()]
  def degenerate_gaps, do: List.duplicate(0, 32)

  @doc "Builds a little-endian libpcap binary from sizes and inter-packet gaps (ms)."
  @spec build([non_neg_integer()], [non_neg_integer()]) :: binary()
  def build(sizes, gaps_ms) do
    global =
      <<0xD4, 0xC3, 0xB2, 0xA1, 2::unsigned-16-little, 4::unsigned-16-little,
        0::unsigned-32-little, 0::unsigned-32-little, 65_535::unsigned-32-little,
        1::unsigned-32-little>>

    records =
      sizes
      |> Enum.zip(ts_from_gaps(gaps_ms))
      |> Enum.map_join(fn {size, ts} ->
        sec = trunc(ts)
        usec = trunc((ts - sec) * 1_000_000)

        <<sec::unsigned-32-little, usec::unsigned-32-little, size::unsigned-32-little,
          size::unsigned-32-little>> <> :binary.copy(<<0xAB>>, size)
      end)

    global <> records
  end

  defp ts_from_gaps(gaps_ms) do
    {ts_list, _} =
      Enum.map_reduce(gaps_ms, 0.0, fn gap_ms, acc ->
        acc = acc + gap_ms / 1000.0
        {acc, acc}
      end)

    [0.0 | ts_list]
  end
end
