defmodule TrafficAudit.PipelineTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias TrafficAudit.Domain.{FlowStats, PcapFixture, Types}
  alias TrafficAudit.Pipeline

  @pcap PcapFixture.build(PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps())

  describe "score_transport/2" do
    test "runs capture -> dpi -> ja3 -> scoring and returns the scored map" do
      opts = [
        capture_fn: fn _t, _o -> {:ok, @pcap} end,
        dpi_fn: fn _ -> {:ok, %{confidence: 0.9}} end,
        ja3_fn: fn _ -> {:ok, ["ja3:abc"]} end
      ]

      assert {:ok, result} = Pipeline.score_transport(:obfs4, opts)
      assert result.transport == :obfs4
      assert result.l2_dpi == %{confidence: 0.9}
      assert %Types.Score{transport: :obfs4} = result.l3_flow
      assert result.l4_ja3 == ["ja3:abc"]

      assert result.composite_score ==
               FlowStats.composite(
                 result.l2_dpi,
                 result.l3_flow,
                 result.l3_flow.l4_ja3_match
               )
    end

    test "scores captured hashes against the browser reference for L4" do
      opts = [
        capture_fn: fn _t, _o -> {:ok, @pcap} end,
        dpi_fn: fn _ -> {:ok, %{confidence: 0.9}} end,
        ja3_fn: fn _ -> {:ok, ["cd08e31494f9531f560d64c695473da9"]} end
      ]

      assert {:ok, result} = Pipeline.score_transport(:obfs4, opts)
      assert result.l3_flow.l4_ja3_match == 1.0
    end

    test "skips the tshark subprocess for non-TLS transports on the production path" do
      opts = [
        capture_fn: fn _t, _o -> {:ok, @pcap} end,
        dpi_fn: fn _ -> {:ok, %{confidence: 0.9}} end
      ]

      log =
        capture_log(fn ->
          assert {:ok, result} = Pipeline.score_transport(:obfs4, opts)
          assert result.l4_ja3 == []
          assert result.l3_flow.l4_ja3_match == 0.0
        end)

      refute log =~ "tshark"

      assert {:ok, %{l4_ja3: [], l3_flow: %{l4_ja3_match: match}}} =
               Pipeline.score_transport(:wireguard, opts)

      assert match == 0.0
    end

    test "short-circuits on a capture failure before dpi runs" do
      assert {:error, {:capture_failed, 1, "no"}} =
               Pipeline.score_transport(:obfs4,
                 capture_fn: fn _, _ -> {:error, {:capture_failed, 1, "no"}} end,
                 dpi_fn: fn _ -> raise "dpi must not run" end
               )
    end

    test "short-circuits on a dpi failure before ja3 runs" do
      assert {:error, :dpi_boom} =
               Pipeline.score_transport(:obfs4,
                 capture_fn: fn _, _ -> {:ok, @pcap} end,
                 dpi_fn: fn _ -> {:error, :dpi_boom} end,
                 ja3_fn: fn _ -> raise "ja3 must not run" end
               )
    end

    test "short-circuits on a ja3 failure before scoring" do
      assert {:error, :ja3_boom} =
               Pipeline.score_transport(:obfs4,
                 capture_fn: fn _, _ -> {:ok, @pcap} end,
                 dpi_fn: fn _ -> {:ok, %{confidence: 0.5}} end,
                 ja3_fn: fn _ -> {:error, :ja3_boom} end
               )
    end

    test "uses the real fixture capture in fixture mode" do
      opts = [
        mode: "fixture",
        dpi_fn: fn _ -> {:ok, %{confidence: 0.5}} end,
        ja3_fn: fn _ -> {:ok, []} end
      ]

      assert {:ok, %{transport: :obfs4, l3_flow: %Types.Score{}}} =
               Pipeline.score_transport(:obfs4, opts)
    end
  end
end
