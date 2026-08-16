defmodule TrafficAudit.PersistenceTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias TrafficAudit.Domain.FlowStats
  alias TrafficAudit.Domain.Types
  alias TrafficAudit.Persistence

  defp winner(transport \\ :obfs4) do
    score =
      FlowStats.score_from_packets(
        [%Types.Packet{size: 1408, direction: :in, ts: 0.0}],
        transport,
        []
      )

    %{transport: transport, l3_flow: score, composite_score: score.composite}
  end

  describe "save/3 in log mode (default)" do
    test "records a structured log line and returns {:ok, :recorded}" do
      log =
        capture_log(fn ->
          assert {:ok, :recorded} = Persistence.save("deadbeef1234", winner())
        end)

      assert log =~ "traffic_audit score recorded"
      assert log =~ "deadbeef"
      assert log =~ "obfs4"
    end

    test "records a composite that includes the L4 ja3-match term" do
      weights = [l1: 0.15, l2: 0.20, l3_size: 0.25, l3_timing: 0.25, l4: 0.15]
      packets = [%Types.Packet{size: 1408, direction: :in, ts: 0.0}]

      with_l4 =
        FlowStats.score_from_packets(packets, :tls_fronted, l4_ja3_match: 0.8, weights: weights)

      without_l4 =
        FlowStats.score_from_packets(packets, :tls_fronted, l4_ja3_match: 0.0, weights: weights)

      assert_in_delta with_l4.composite - without_l4.composite, 0.8 * 0.15, 1.0e-12

      log =
        capture_log(fn ->
          assert {:ok, :recorded} =
                   Persistence.save(
                     "deadbeef1234",
                     %{
                       transport: :tls_fronted,
                       l3_flow: with_l4,
                       composite_score: with_l4.composite
                     }
                   )
        end)

      assert log =~ "tls_fronted"
      assert log =~ Float.to_string(with_l4.composite)
    end
  end

  describe "save/3 in repo mode" do
    test "errors cleanly when the Repo is not started (Option A dormant)" do
      assert {:error, {kind, _reason}} = Persistence.save("abc123", winner(), mode: :repo)
      assert kind in [:error, :exit]
    end
  end
end
