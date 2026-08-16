defmodule TrafficAudit.Io.DpiTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Io.Dpi

  setup do
    dir = Path.join(System.tmp_dir!(), "dpi_fake_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    on_exit(fn -> File.rm_rf!(dir) end)

    %{dir: dir}
  end

  defp fake_ndpi_reader(dir, body) do
    path = Path.join(dir, "ndpiReader")
    File.write!(path, "#!/bin/sh\n#{body}")
    File.chmod!(path, 0o755)
    path
  end

  describe "scan/2" do
    test "returns the parsed classification summary", %{dir: dir} do
      path =
        fake_ndpi_reader(dir, ~S"""
          echo 'Using nDPI (4.2.0) [1 thread(s)]'
          echo 'Unique flows:          2'
          echo 'Confidence: DPI          2             (flows)'
          echo 'Detected protocols:'
          echo '	TLS                 packets:           120 bytes:         44000 flows:            2'
        """)

      assert {:ok, summary} = Dpi.scan("", find_executable_fn: fn _ -> path end)

      assert summary == %{
               version: "4.2.0",
               packets: %{ip: 0, total: 0},
               flows: 2,
               protocols: %{"TLS" => %{packets: 120, bytes: 44_000, flows: 2}},
               confidence: 1.0
             }
    end

    test "propagates a missing binary" do
      assert {:error, {:command_not_found, "ndpiReader"}} =
               Dpi.scan("", find_executable_fn: fn _ -> nil end)
    end

    test "propagates ndpiReader failures", %{dir: dir} do
      path =
        fake_ndpi_reader(dir, ~S"""
          echo 'ndpiReader: cannot open pcap' >&2
          exit 1
        """)

      assert {:error, {:command_failed, "ndpiReader", 1, err}} =
               Dpi.scan("", find_executable_fn: fn _ -> path end)

      assert err =~ "cannot open pcap"
    end
  end
end
