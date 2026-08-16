defmodule TrafficAudit.CLI do
  @moduledoc """
  Escript entry point for `traffic_audit`.

      traffic-audit run COMMIT_SHA            # run the CI gate for a commit
      traffic-audit help                      # usage
  """

  def main(argv) do
    case run(argv) do
      {:ok, result} ->
        IO.puts(Jason.encode!(result, pretty: true))

      {:error, reason} ->
        IO.puts(:stderr, "error: #{inspect(reason)}")
        System.halt(1)

      {:halt, status, message} ->
        if message, do: IO.puts(message)
        System.halt(status)
    end
  end

  def run(["run", commit]) when is_binary(commit) and byte_size(commit) > 0 do
    case Application.ensure_all_started(:traffic_audit) do
      {:ok, _} -> TrafficAudit.run(commit)
      {:error, reason} -> {:error, reason}
    end
  end

  def run(["run", _commit, "--transport=" <> _t]) do
    # Transport override is not supported yet — reject rather than auditing
    # every transport.
    {:halt, 64, usage()}
  end

  def run(["--help"]), do: {:halt, 0, usage()}
  def run(["help"]), do: {:halt, 0, usage()}
  def run([]), do: {:halt, 0, usage()}
  def run(_), do: {:halt, 64, usage()}

  defp usage do
    """
    traffic-audit — per-commit ISP-fingerprint CI gate

        traffic-audit run COMMIT_SHA
        traffic-audit help

    Environment:

        TRAFFIC_AUDIT_CAPTURE_MODE   "live" (default) | "fixture"
    """
  end
end
