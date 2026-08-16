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
  end

  describe "save/3 in repo mode" do
    test "errors cleanly when the Repo is not started (Option A dormant)" do
      assert {:error, {kind, _reason}} = Persistence.save("abc123", winner(), mode: :repo)
      assert kind in [:error, :exit]
    end
  end
end
