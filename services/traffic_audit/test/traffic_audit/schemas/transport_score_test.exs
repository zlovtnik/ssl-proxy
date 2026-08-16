defmodule TrafficAudit.Schemas.TransportScoreTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Domain.{FlowStats, Types}
  alias TrafficAudit.Schemas.TransportScore

  describe "to_attrs/2" do
    test "maps a domain Score into the transport_scores column set" do
      score =
        FlowStats.score_from_packets(
          [
            %Types.Packet{size: 1408, direction: :in, ts: 0.0},
            %Types.Packet{size: 72, direction: :out, ts: 0.01}
          ],
          :obfs4,
          commit_sha: "abc123"
        )

      attrs = TransportScore.to_attrs(score, commit_sha: "abc123")

      assert attrs.__struct__ == TransportScore
      assert attrs.commit_sha == "abc123"
      assert attrs.transport == "obfs4"
      assert attrs.l3_size_divergence == Decimal.from_float(score.l3_size_divergence)
      assert attrs.composite_score == Decimal.from_float(score.composite)
      assert attrs.selected == false
      assert Map.has_key?(attrs, :inserted_at)
      assert Map.has_key?(attrs, :updated_at)
    end

    test "carries the L1-L4 fields when present" do
      score = %Types.Score{
        transport: :tls_fronted,
        l1: 0.9,
        l2: %{transport: :tls_fronted, confidence: 0.95},
        l3_size_divergence: 0.05,
        l3_timing_divergence: 0.06,
        l4_ja3_match: 0.8,
        composite: 0.2,
        passed?: true
      }

      attrs = TransportScore.to_attrs(score, commit_sha: "deadbeef")

      assert attrs.l1_score == Decimal.from_float(0.9)
      assert attrs.l2_score == Decimal.from_float(0.95)
      assert attrs.l4_ja3_match == Decimal.from_float(0.8)
    end
  end
end
