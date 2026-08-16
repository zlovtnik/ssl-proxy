defmodule TrafficAudit.Domain.DpiSummaryTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Domain.DpiSummary

  @summary """
  -----------------------------------------------------------
  * NOTE: This is demo app to show *some* nDPI features.
  ------------------------------------------------------------

  Using nDPI (4.2.0) [1 thread(s)]
  Using libgcrypt version 1.10.3

  Reading packets from pcap file /tmp/traffic_audit_123.pcap...
  Running thread 0...

  nDPI Memory statistics:
  \tndpi_malloc calls:     1512

  Traffic statistics:
  \tIP packets:            148 of 150 packets total
  \tIP bytes:              95000 of 96000 bytes total
  \tUnique flows:          20
  \tTCP flows:             18
  \tUDP flows:             2
  \tOther flows:           0
  \tConfidence: DPI          12            (flows)
  \tConfidence: DPI Partial  4             (flows)
  \tConfidence: Unknown      5             (flows)
  \tConfidence: Speculative  3             (flows)

  Detected protocols:
  \tTLS                 packets:           120 bytes:         44000 flows:            2
  \tQUIC                packets:            28 bytes:         50000 flows:            1
  \tAmazon AWS          packets:             0 bytes:             0 flows:            1
  \tcorrupted row without labels

  Protocol statistics:
  \tTCP                 148

  Undetected flows: 0 (0.00 %)
  """

  describe "parse/1" do
    test "parses the version, totals, protocol table and confidence" do
      assert DpiSummary.parse(@summary) == %{
               version: "4.2.0",
               packets: %{ip: 148, total: 150},
               flows: 20,
               protocols: %{
                 "TLS" => %{packets: 120, bytes: 44_000, flows: 2},
                 "QUIC" => %{packets: 28, bytes: 50_000, flows: 1},
                 "Amazon AWS" => %{packets: 0, bytes: 0, flows: 1}
               },
               confidence: 16.0 / 24.0
             }
    end

    test "counts only Unknown and Speculative as untrusted" do
      summary = DpiSummary.parse(@summary)
      assert_in_delta summary.confidence, 0.666, 0.001
    end

    test "confidence is 0.0 when every flow is Unknown or Speculative" do
      out = """
      \tConfidence: Unknown      5             (flows)
      \tConfidence: Speculative  3             (flows)
      """

      assert DpiSummary.parse(out).confidence == 0.0
    end

    test "confidence is 1.0 when nothing is untrusted" do
      out = "\tConfidence: DPI          12            (flows)\n"
      assert DpiSummary.parse(out).confidence == 1.0
    end

    test "confidence math on exact halves" do
      out = """
      \tConfidence: DPI          12            (flows)
      \tConfidence: Unknown      5             (flows)
      \tConfidence: Speculative  3             (flows)
      """

      assert DpiSummary.parse(out).confidence == 0.6
    end

    test "stops the protocol table at Protocol statistics and skips junk rows" do
      summary = DpiSummary.parse(@summary)

      refute Map.has_key?(summary.protocols, "TCP"),
             "the Protocol statistics breed row must not leak into the table"

      assert Map.has_key?(summary.protocols, "TLS"),
             "a corrupted row must not stop table parsing"
    end

    test "returns zeros when no summary block is present" do
      assert DpiSummary.parse("") == %{
               version: nil,
               packets: %{ip: 0, total: 0},
               flows: 0,
               protocols: %{},
               confidence: 0.0
             }

      assert DpiSummary.parse("Using nDPI (4.2.0)\n") == %{
               version: "4.2.0",
               packets: %{ip: 0, total: 0},
               flows: 0,
               protocols: %{},
               confidence: 0.0
             }
    end
  end
end
