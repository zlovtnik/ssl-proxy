defmodule TrafficAudit.Io.Ja3Test do
  use ExUnit.Case, async: true

  alias TrafficAudit.Io.Ja3

  describe "parse/1" do
    test "maps each -T fields ClientHello line to its unique 32-hex JA3 hash" do
      out = """
      771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
      769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
      771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
      """

      assert Ja3.parse(out) == [
               "cd08e31494f9531f560d64c695473da9",
               "ada70206e40642a3e4461f35503241d5"
             ]
    end

    test "returns [] when no ClientHello lines are present" do
      assert Ja3.parse("no fingerprints here") == []
      assert Ja3.parse("") == []
    end
  end
end

defmodule TrafficAudit.Io.Ja3ExtractTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias TrafficAudit.Io.Ja3

  setup do
    dir = Path.join(System.tmp_dir!(), "ja3_fake_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    on_exit(fn -> File.rm_rf!(dir) end)

    %{dir: dir}
  end

  defp fake_tshark(dir, body) do
    path = Path.join(dir, "tshark")
    File.write!(path, "#!/bin/sh\n#{body}")
    File.chmod!(path, 0o755)
    path
  end

  describe "extract/2" do
    test "returns hashes parsed from -T fields output", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0'
        """)

      assert {:ok, ["cd08e31494f9531f560d64c695473da9"]} =
               Ja3.extract("", find_executable_fn: fn _ -> path end)
    end

    test "skips lines that do not parse into a hash", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo 'not,a,valid,line'
        """)

      assert {:ok, []} = Ja3.extract("", find_executable_fn: fn _ -> path end)
    end

    test "degrades to {:ok, []} when tshark is missing" do
      assert capture_log(fn ->
               assert {:ok, []} = Ja3.extract("", find_executable_fn: fn _ -> nil end)
             end) =~ "JA3"
    end

    test "propagates other tshark failures", %{dir: dir} do
      path =
        fake_tshark(dir, ~S"""
          echo 'tshark: some other failure' >&2
          exit 1
        """)

      assert {:error, {:command_failed, "tshark", 1, err}} =
               Ja3.extract("", find_executable_fn: fn _ -> path end)

      assert err =~ "some other failure"
    end
  end
end
