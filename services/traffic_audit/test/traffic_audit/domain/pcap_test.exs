defmodule TrafficAudit.Domain.PcapTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Domain.Pcap

  describe "parse/1" do
    # magic (0xA1B2C3D4 little-endian bytes) | ver_major | ver_minor | thiszone | sigfigs | snaplen | network
    @global <<0xD4, 0xC3, 0xB2, 0xA1, 0::unsigned-16-little, 0::unsigned-16-little,
              0::unsigned-32-little, 0::unsigned-32-little, 0::unsigned-32-little,
              1::unsigned-32-little>>

    # record: ts_sec | ts_usec | incl_len | orig_len + frame bytes
    @record <<1000::unsigned-32-little, 500_000::unsigned-32-little, 64::unsigned-32-little,
              64::unsigned-32-little>> <> <<0::512>>

    test "parses little-endian global header + one record" do
      packets = Pcap.parse(@global <> @record)
      assert length(packets) == 1
      # ts = 1000 + 0.5 = 1000.5; size = 64
      [%TrafficAudit.Domain.Types.Packet{size: 64, ts: ts}] = packets
      assert_in_delta ts, 1000.5, 1.0e-6
    end

    test "returns [] for a truncated header" do
      assert Pcap.parse(<<1, 2, 3>>) == []
    end

    test "returns [] for empty input" do
      assert Pcap.parse(<<>>) == []
    end

    test "parses multiple records in order" do
      rec2 =
        <<2000::unsigned-32-little, 0::unsigned-32-little, 48::unsigned-32-little,
          48::unsigned-32-little>> <> <<0::384>>

      packets = Pcap.parse(@global <> @record <> rec2)
      assert length(packets) == 2
      assert Enum.map(packets, & &1.size) == [64, 48]
    end

    test "handles big-endian magic" do
      global_be =
        <<0xA1, 0xB2, 0xC3, 0xD4, 0::unsigned-16-big, 0::unsigned-16-big, 0::unsigned-32-big,
          0::unsigned-32-big, 0::unsigned-32-big, 1::unsigned-32-big>>

      rec_be =
        <<1000::unsigned-32-big, 500_000::unsigned-32-big, 64::unsigned-32-big,
          64::unsigned-32-big>> <> <<0::512>>

      packets = Pcap.parse(global_be <> rec_be)
      assert length(packets) == 1
      [%TrafficAudit.Domain.Types.Packet{size: 64, ts: ts}] = packets
      assert_in_delta ts, 1000.5, 1.0e-6
    end
  end
end
