# Regenerates the deterministic pcap fixtures used by fixture-mode captures and
# CI. Run from the service root:
#
#     mix run scripts/generate_fixtures.exs
#
# Each transport's fixture is a valid little-endian libpcap file with a
# realistic HTTPS-ish mix of packet sizes and inter-packet gaps, so scoring
# against `TrafficAudit.Domain.FlowStats.reference_https/0` is meaningful:
#
#   - obfs4       mimics the reference distribution closely (gate-passing, low divergence)
#   - wireguard   slightly skewed sizes (gate-passing, higher divergence)
#   - tls_fronted degenerate burst of full-size packets (fails the 0.20 gate)
#
# Output is written to priv/fixtures/<transport>.pcap and is intended to be
# committed.

defmodule FixtureGenerator do
  @sizes_ref [0, 0, 64, 64, 64, 128, 128, 256, 256, 256, 256, 512, 512, 512, 512, 512, 512,
              1408, 1408, 1408, 1408, 1408, 1408, 1408, 1408, 1408, 1408, 1408, 1472, 1472,
              1472, 1472, 1472]
  @gaps_ref_ms [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10, 10, 10, 20, 20, 20, 20,
                30, 30, 30, 30, 40, 40, 40, 60, 60, 80, 80]

  def run do
    dir = Path.join(File.cwd!(), "priv/fixtures")
    File.mkdir_p!(dir)

    fixtures = [
      {:obfs4, @sizes_ref, @gaps_ref_ms},
      {:wireguard, Enum.map(@sizes_ref, &(&1 + 64)), @gaps_ref_ms},
      {:tls_fronted, List.duplicate(1408, 33), List.duplicate(0, 32)}
    ]

    Enum.each(fixtures, fn {transport, sizes, gaps_ms} ->
      path = Path.join(dir, "#{transport}.pcap")
      File.write!(path, build_pcap(sizes, gaps_ms))
      IO.puts("wrote #{path} (#{byte_size(path |> File.read!())} bytes)")
    end)
  end

  # libpcap global header (little-endian magic, version 2.4, snaplen 65535,
  # network 1 = Ethernet) followed by one record per packet.
  def build_pcap(sizes, gaps_ms) do
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

FixtureGenerator.run()