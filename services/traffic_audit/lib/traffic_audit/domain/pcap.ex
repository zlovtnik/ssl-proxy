defmodule TrafficAudit.Domain.Pcap do
  @moduledoc """
  L0 — a *pure* parser for libpcap (`.pcap`) capture bytes into `Packet` lists.

  No IO whatsoever. Understanding enough of the legacy libpcap global + per-record
  record-header format (little- and big-endian magic) to recover `(ts_seconds,
  ts_useconds, incl_len)` per frame and the captured length as the packet size.

  Direction is recorded as `:in` for every frame (interface origin is not
  encoded in the capture; the size/timing scorers are direction-agnostic today).
  A full link-layer/IP/TCP dissection for richer direction/L4 attribution is a
  future extension.
  """

  alias TrafficAudit.Domain.Types.Packet

  # Standard libpcap magic 0xA1B2C3D4 (2712847316), decoded in both byte orders.
  @magic_le 2_712_847_316
  @magic_be 2_712_847_316

  @doc "Parses libpcap bytes into a chronologically-ordered list of packets."
  @spec parse(iodata()) :: [Packet.t()]
  def parse(iodata) do
    bin = :erlang.iolist_to_binary(iodata)

    case global(bin) do
      {:ok, body, _network, endian} -> parse_records(body, [], endian)
      :error -> []
    end
  end

  @spec global(binary()) :: {:ok, binary(), non_neg_integer(), :le | :be} | :error
  defp global(
         <<@magic_le::unsigned-32-little, _ver_major::unsigned-16-little,
           _ver_minor::unsigned-16-little, _thiszone::unsigned-32-little,
           _sigfigs::unsigned-32-little, _snaplen::unsigned-32-little,
           network::unsigned-32-little, rest::binary>>
       ) do
    {:ok, rest, network, :le}
  end

  defp global(
         <<@magic_be::unsigned-32-big, _ver_major::unsigned-16-big, _ver_minor::unsigned-16-big,
           _thiszone::unsigned-32-big, _sigfigs::unsigned-32-big, _snaplen::unsigned-32-big,
           network::unsigned-32-big, rest::binary>>
       ) do
    {:ok, rest, network, :be}
  end

  defp global(_), do: :error

  defp parse_records(<<>>, acc, _endian), do: Enum.reverse(acc)

  defp parse_records(
         <<ts_sec::unsigned-32-little, ts_usec::unsigned-32-little, incl_len::unsigned-32-little,
           _orig::unsigned-32-little, rest::binary>>,
         acc,
         :le
       ) do
    {frame, remaining} = split_frame(rest, incl_len)
    packet = %Packet{size: byte_size(frame), direction: :in, ts: ts_sec + ts_usec / 1_000_000.0}
    parse_records(remaining, [packet | acc], :le)
  end

  defp parse_records(
         <<ts_sec::unsigned-32-big, ts_usec::unsigned-32-big, incl_len::unsigned-32-big,
           _orig::unsigned-32-big, rest::binary>>,
         acc,
         :be
       ) do
    {frame, remaining} = split_frame(rest, incl_len)
    packet = %Packet{size: byte_size(frame), direction: :in, ts: ts_sec + ts_usec / 1_000_000.0}
    parse_records(remaining, [packet | acc], :be)
  end

  # A record header that claims a frame larger than the bytes available is
  # truncated: take what's present (matches libpcap behaviour for partial reads).
  defp parse_records(_, acc, _endian), do: Enum.reverse(acc)

  defp split_frame(bin, n) when byte_size(bin) >= n do
    {binary_part(bin, 0, n), binary_part(bin, n, byte_size(bin) - n)}
  end

  defp split_frame(bin, _n), do: {bin, <<>>}
end
