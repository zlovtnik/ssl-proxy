defmodule TrafficAudit.Io.Ja3Test do
  use ExUnit.Case, async: true

  alias TrafficAudit.Io.Ja3

  describe "parse/1" do
    test "extracts unique 32-hex JA3 hashes from tshark ja3,tree output" do
      out = """
      Client "JA3 Fingerprint": 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
      Client "JA3 Hash": 0f9a5d9a2f4d8e1c3b7a6e5d4c3b2a1f
      Server "JA3 Fingerprint": 771,4865-4866-4867-49195-49199-49196-49200-52393-52392
      Server "JA3 Hash": 6e5d4c3b2a1f0f9a5d9a2f4d8e1c3b7a
      """

      assert Ja3.parse(out) == [
               "0f9a5d9a2f4d8e1c3b7a6e5d4c3b2a1f",
               "6e5d4c3b2a1f0f9a5d9a2f4d8e1c3b7a"
             ]
    end

    test "returns [] when no hashes are present" do
      assert Ja3.parse("no fingerprints here") == []
    end
  end
end

defmodule TrafficAudit.Io.Ja3ExtractTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias TrafficAudit.Io.Ja3

  setup do
    dir = Path.join(System.tmp_dir!(), "ja3_fake_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    on_exit(fn -> File.rm_rf!(dir) end)

    old_path = System.get_env("PATH")

    on_exit(fn ->
      if old_path, do: System.put_env("PATH", old_path), else: System.delete_env("PATH")
    end)

    %{dir: dir}
  end

  defp fake_tshark(dir, body) do
    path = Path.join(dir, "tshark")
    File.write!(path, "#!/bin/sh\n#{body}")
    File.chmod!(path, 0o755)
    path
  end

  describe "extract/1" do
    test "returns parsed hashes when tshark supports ja3,tree", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo 'Client "JA3 Hash": 0f9a5d9a2f4d8e1c3b7a6e5d4c3b2a1f'
        """)

      System.put_env("PATH", Path.dirname(path))
      assert {:ok, ["0f9a5d9a2f4d8e1c3b7a6e5d4c3b2a1f"]} = Ja3.extract("")
    end

    test "degrades to {:ok, []} when tshark reports ja3,tree unsupported", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo 'tshark: Invalid -z argument "ja3,tree"; it must be one of:' >&2
          echo '     afp,srt' >&2
          exit 1
        """)

      System.put_env("PATH", Path.dirname(path))

      assert capture_log(fn ->
               assert {:ok, []} = Ja3.extract("")
             end) =~ "JA3"
    end

    test "degrades to {:ok, []} when tshark is missing" do
      empty = Path.join(System.tmp_dir!(), "ja3_empty_#{System.unique_integer([:positive])}")
      File.mkdir_p!(empty)
      on_exit(fn -> File.rm_rf!(empty) end)

      System.put_env("PATH", empty)

      assert capture_log(fn ->
               assert {:ok, []} = Ja3.extract("")
             end) =~ "JA3"
    end

    test "propagates other tshark failures", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo 'tshark: some other failure' >&2
          exit 1
        """)

      System.put_env("PATH", Path.dirname(path))

      assert {:error, {:command_failed, "tshark", 1, err}} = Ja3.extract("")
      assert err =~ "some other failure"
    end
  end
end
