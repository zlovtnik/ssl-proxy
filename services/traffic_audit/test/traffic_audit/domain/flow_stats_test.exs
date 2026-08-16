defmodule TrafficAudit.Domain.FlowStatsTest do
  use ExUnit.Case, async: true
  use ExUnitProperties, async: true

  import TrafficAudit.Domain.FlowStats
  alias TrafficAudit.Domain.{FlowStats, Generators, Types}

  describe "size_histogram/1" do
    test "quantizes sizes into 64-byte buckets" do
      packets = [
        %Types.Packet{size: 10, direction: :in, ts: 0.0},
        %Types.Packet{size: 70, direction: :in, ts: 0.01},
        %Types.Packet{size: 75, direction: :in, ts: 0.02},
        %Types.Packet{size: 64, direction: :out, ts: 0.03}
      ]

      %{buckets: buckets} = size_histogram(packets)
      # 10 -> bucket 0; 70 -> 64; 75 -> 64; 64 -> 64
      assert buckets[0] == 1
      assert buckets[64] == 3
    end

    property "is well-formed for any packet list" do
      check all(packets <- Generators.packets()) do
        %{buckets: buckets} = size_histogram(packets)
        assert is_map(buckets)
        assert Enum.all?(buckets, fn {k, v} -> is_integer(k) and v > 0 end)
        assert map_size(buckets) > 0
      end
    end
  end

  describe "timing_histogram/1" do
    test "quantizes inter-packet gaps into 10ms buckets" do
      packets = [
        %Types.Packet{size: 100, direction: :in, ts: 0.0},
        %Types.Packet{size: 100, direction: :in, ts: 0.015},
        %Types.Packet{size: 100, direction: :in, ts: 0.035}
      ]

      %{buckets: buckets} = timing_histogram(packets)
      # gaps: 15ms -> bucket 10; 20ms -> bucket 20
      assert buckets[10] == 1
      assert buckets[20] == 1
    end
  end

  describe "js_divergence/2" do
    property "is 0.0 for identical histograms" do
      check all(packets <- Generators.packets()) do
        h = size_histogram(packets)
        assert js_divergence(h, h) == 0.0
      end
    end

    property "is symmetric" do
      check all(
              a <- Generators.packets(),
              b <- Generators.packets()
            ) do
        ha = size_histogram(a)
        hb = size_histogram(b)
        assert_jsd_equal(js_divergence(ha, hb), js_divergence(hb, ha))
      end
    end

    property "is bounded in [0.0, 1.0]" do
      check all(
              a <- Generators.packets(),
              b <- Generators.packets()
            ) do
        d = js_divergence(size_histogram(a), size_histogram(b))
        assert d >= 0.0
        assert d <= 1.0
      end
    end

    test "empty-vs-empty is 0.0" do
      assert js_divergence(%Types.Histogram{buckets: %{}}, %Types.Histogram{buckets: %{}}) == 0.0
    end
  end

  describe "score_from_packets/3 and score/3" do
    property "returns a Score with composite in [0,1] and a boolean gate" do
      check all(packets <- Generators.packets()) do
        %Types.Score{} = score = score_from_packets(packets, :obfs4, [])

        assert is_float(score.composite)
        assert score.composite >= 0.0
        assert score.composite <= 1.0
        assert is_boolean(score.passed?)
      end
    end

    test "score/3 parses a pcap and equals score_from_packets/3" do
      # libpcap little-endian magic (0xA1B2C3D4) + zeroed header fields,
      # then a single 64-byte record — mirrors pcap_test.exs.
      header =
        <<0xD4, 0xC3, 0xB2, 0xA1, 0::unsigned-16-little, 0::unsigned-16-little,
          0::unsigned-32-little, 0::unsigned-32-little, 0::unsigned-32-little,
          1::unsigned-32-little>>

      record =
        <<0::unsigned-32-little, 0::unsigned-32-little, 64::unsigned-32-little,
          64::unsigned-32-little>> <> <<0::512>>

      pcap = header <> record

      via_pcap = score(pcap, :obfs4, [])

      via_packets =
        score_from_packets([%Types.Packet{size: 64, direction: :in, ts: 0.0}], :obfs4, [])

      assert via_pcap.l3_size_divergence == via_packets.l3_size_divergence
    end

    test "empty capture fails the 0.20 gate" do
      score = score_from_packets([], :obfs4, [])
      refute score.passed?
      assert score.l3_size_divergence > 0.20
    end
  end

  defp assert_jsd_equal(a, b), do: assert_in_delta(a, b, 1.0e-9)

  describe "composite/3" do
    test "blends l2 confidence, l3 divergences, and l4 match with fixed weights" do
      flow = %{l1: 0.0, l3_size_divergence: 0.10, l3_timing_divergence: 0.20}
      # 0.25 * 0.8 + 0.30 * 0.10 + 0.30 * 0.20 + 0.0 * 0.5 = 0.29
      assert_in_delta FlowStats.composite(%{confidence: 0.8}, flow, 0.5), 0.29, 1.0e-9
    end

    test "is bounded in [0, 1] for extreme inputs" do
      flow = %{l1: 0.0, l3_size_divergence: 5.0, l3_timing_divergence: -1.0}
      assert FlowStats.composite(%{confidence: 2.0}, flow, 9.0) == 1.0

      assert FlowStats.composite(
               nil,
               %{l1: nil, l3_size_divergence: 0.0, l3_timing_divergence: 0.0},
               nil
             ) == 0.0
    end

    test "a raw JA3 fingerprint list scores 0.0 for l4" do
      flow = %{l1: 0.0, l3_size_divergence: 0.0, l3_timing_divergence: 0.0}
      assert FlowStats.composite(%{confidence: 1.0}, flow, ["ja3:abc"]) == 0.25
    end
  end

  describe "reference_https/0" do
    test "returns two non-empty histograms" do
      {size, timing} = reference_https()
      assert map_size(size.buckets) > 0
      assert map_size(timing.buckets) > 0
    end
  end
end
