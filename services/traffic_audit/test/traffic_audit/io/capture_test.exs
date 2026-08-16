defmodule TrafficAudit.Io.CaptureTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Io.Capture

  describe "run/2 in fixture mode" do
    test "reads the committed fixture for a known transport" do
      assert {:ok, pcap} = Capture.run(:obfs4, mode: "fixture")
      assert <<0xD4, 0xC3, 0xB2, 0xA1, _::binary>> = pcap
    end

    test "returns an error for an unknown transport" do
      assert {:error, {:fixture_missing, _path, :enoent}} =
               Capture.run(:not_a_transport, mode: "fixture")
    end
  end
end
