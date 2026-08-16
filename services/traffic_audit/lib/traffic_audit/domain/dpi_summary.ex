defmodule TrafficAudit.Domain.DpiSummary do
  @moduledoc """
  Parses `ndpiReader`'s text output into a structured classification summary.

  The Debian bookworm `libndpi-bin` (nDPI 4.2.0) ndpiReader has no JSON flow
  dump: `-J` is a dead getopt entry that prints help and exits, and `-q`
  suppresses the statistics block entirely. The default output is therefore the
  source of truth — a banner followed by a stats block — and the parse anchors
  on the printed headers (`Traffic statistics`, `Detected protocols`,
  `Confidence:`) so it survives reordering inside the block.

  The derived `:confidence` is the share of flows nDPI did not leave Unknown or
  Speculative (port-guessed); it feeds the L2 score in
  `TrafficAudit.Domain.FlowStats`. Missing output parses to zeros, matching the
  scorer's treatment of a missing `:confidence`.
  """

  @untrusted_confidences ~w(Unknown Speculative)

  @spec parse(binary()) :: map()
  def parse(output) do
    %{
      version: version(output),
      packets: packets(output),
      flows: flows(output),
      protocols: protocols(output),
      confidence: confidence(output)
    }
  end

  @spec version(binary()) :: String.t() | nil
  defp version(output) do
    case Regex.run(~r/Using nDPI \(([^)]+)\)/, output) do
      [_, v] -> v
      _ -> nil
    end
  end

  @spec packets(binary()) :: %{ip: non_neg_integer(), total: non_neg_integer()}
  defp packets(output) do
    case Regex.run(~r/IP packets:\s+(\d+) of (\d+) packets total/, output) do
      [_, ip, total] -> %{ip: String.to_integer(ip), total: String.to_integer(total)}
      _ -> %{ip: 0, total: 0}
    end
  end

  @spec flows(binary()) :: non_neg_integer()
  defp flows(output) do
    case Regex.run(~r/Unique flows:\s+(\d+)/, output) do
      [_, n] -> String.to_integer(n)
      _ -> 0
    end
  end

  @spec protocols(binary()) :: %{optional(String.t()) => map()}
  defp protocols(output) do
    {_, acc} =
      output
      |> String.split("\n")
      |> Enum.reduce({false, %{}}, fn line, {in_table, acc} ->
        cond do
          String.starts_with?(line, "Detected protocols:") -> {true, acc}
          String.starts_with?(line, "Protocol statistics:") -> {false, acc}
          in_table -> {true, put_protocol(acc, line)}
          true -> {in_table, acc}
        end
      end)

    acc
  end

  defp put_protocol(acc, line) do
    case Regex.run(
           ~r/^\t(.+?)\s+packets:\s+(\d+)\s+bytes:\s+(\d+)\s+flows:\s+(\d+)$/,
           line
         ) do
      [_, name, packets, bytes, flows] ->
        Map.put(acc, name, %{
          packets: String.to_integer(packets),
          bytes: String.to_integer(bytes),
          flows: String.to_integer(flows)
        })

      _ ->
        acc
    end
  end

  @spec confidence(binary()) :: float()
  defp confidence(output) do
    {total, untrusted} =
      Enum.reduce(Regex.scan(~r/Confidence:\s+(.+?)\s+(\d+)\s+\(flows\)/, output), {0, 0}, fn [
                                                                                                _,
                                                                                                name,
                                                                                                n
                                                                                              ],
                                                                                              {total,
                                                                                               untrusted} ->
        count = String.to_integer(n)
        untrusted = if name in @untrusted_confidences, do: untrusted + count, else: untrusted
        {total + count, untrusted}
      end)

    if total == 0, do: 0.0, else: (total - untrusted) / total
  end
end
