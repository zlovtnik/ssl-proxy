defmodule TrafficAudit.Io.Shell do
  @moduledoc """
  The one shared subprocess wrapper used by the `io/` layer.

  Every module in `io/` funnels its invocation through here so the plumbing
  (input delivery, exit-status handling, cleanup) exists exactly once — no
  macros required.

  `System.cmd/3` cannot feed stdin, so `run_with_input/4` stages the input
  bytes in a temp file, appends `[input_flag, path]` to the args, and removes
  the file afterwards. Both current consumers (`tshark -r FILE`,
  `ndpiReader -i FILE`) accept a path this way.
  """

  @doc """
  Runs `bin` with `args`, feeding `input` as a temp file referenced by
  `input_flag`, and returns the merged output. Exit status 0 is success;
  anything else is `{:error, ...}`.
  """
  @spec run_with_input(String.t(), [String.t()], iodata(), String.t()) ::
          {:ok, binary()} | {:error, term()}
  def run_with_input(bin, args, input, input_flag) do
    case System.find_executable(bin) do
      nil ->
        {:error, {:command_not_found, bin}}

      path ->
        run_with_path(bin, path, args, input, input_flag)
    end
  end

  defp run_with_path(bin, path, args, input, input_flag) do
    tmp =
      Path.join(System.tmp_dir!(), "traffic_audit_#{System.unique_integer([:positive])}.pcap")

    try do
      fd = File.open!(tmp, [:write, :exclusive, :binary])
      File.chmod!(tmp, 0o600)
      IO.binwrite(fd, input)
      File.close(fd)

      case System.cmd(path, args ++ [input_flag, tmp], stderr_to_stdout: true) do
        {out, 0} -> {:ok, out}
        {out, code} -> {:error, {:command_failed, bin, code, out}}
      end
    after
      File.rm(tmp)
    end
  end
end
