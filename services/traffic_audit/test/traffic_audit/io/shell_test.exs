defmodule TrafficAudit.Io.ShellTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Io.Shell

  describe "run_with_input/4" do
    test "stages the input as a file and returns stdout on exit 0" do
      assert {:ok, "hello\n"} = Shell.run_with_input("cat", [], "hello\n", "-u")
    end

    test "returns an error tuple on non-zero exit" do
      assert {:error, {:command_failed, "false", 1, ""}} =
               Shell.run_with_input("false", [], "", "x")
    end

    test "returns {:error, :command_not_found} when the binary is missing" do
      assert {:error, {:command_not_found, "definitely-not-a-real-binary-xyz"}} =
               Shell.run_with_input("definitely-not-a-real-binary-xyz", [], "", "-i")
    end

    test "surfaces stderr merged into the error output" do
      assert {:error, {:command_failed, "sh", 1, err}} =
               Shell.run_with_input(
                 "sh",
                 ["-c", "cat \"$2\" >&2; exit 1", "traffic_audit_test"],
                 "oops\n",
                 "x"
               )

      assert err =~ "oops"
    end
  end
end
