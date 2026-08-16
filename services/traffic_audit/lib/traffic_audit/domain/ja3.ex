defmodule TrafficAudit.Domain.Ja3 do
  @moduledoc """
  Pure JA3 fingerprint computation from raw tshark `-T fields` lines (no IO).

  JA3 (salesforce/ja3) is the MD5 of the TLS ClientHello's
  `version,ciphers,extensions,groups,point_formats`: comma-separated fields,
  dash-joined decimal values. GREASE values (RFC 8701, `0x?a?a`) are dropped
  from ciphers, extensions, and groups before hashing so the fingerprint
  survives a browser's GREASE rotation.

  `TrafficAudit.Io.Ja3` feeds one comma-separated line per ClientHello here.
  tshark prints `tls.handshake.version` in hex (`0x0303`) and the list fields
  in decimal (`4865`), so every token is normalized to its decimal integer
  first — the resulting JA3 string is the canonical one JA3 databases
  publish, regardless of the Wireshark version that produced the capture.

  `match_score/2` compares captured hashes against a static reference of
  known-browser JA3s (`@browser_ja3s`). Policy: max confidence across all
  ClientHellos in the window — one browser hash is not diluted by non-browser
  hashes on the same page load. Each entry is verified by MD5 of its
  published JA3 string (Chrome, Firefox, Safari, desktop + mobile).
  """

  # Known-browser JA3 hashes, sourced from public JA3 databases (not live
  # capture, so they don't drift with this proxy's own fingerprint). Every
  # hash was verified by computing MD5 of its published JA3 string:
  #   cd08e31494f9531f560d64c695473da9  Chrome (dominant pre-permutation fingerprint, Fastly)
  #   8ed066e87ae52cd04becca471a0b0892  Chrome (post-110 permuted variant, salesforce/ja3#88)
  #   b20b44b18b853ef29ab773e921b03422  Firefox 63.0
  #   334da95730484a993c6063e36bc90a47  Firefox 64.0
  #   ca0f3f4c08cbd372720beb1af7d2721f  Firefox 52
  #   b76d503360ae441d410a85a7f8d648ab  Safari macOS 13.4 (Ventura)
  #   773906b0efdefa24a7f2b8eb6985bf37  Safari iOS 18.3
  #   400961c8161ba7661a7029d3f7e8bb95  Chrome (Android)
  #
  # Refresh cadence for a live baseline is an open item: Chrome 110+ permutes
  # ClientHello extension order, so modern Chrome emits a practically-unique
  # JA3 per connection and only a curated subset of its variants can ever be
  # listed here.
  @browser_ja3s MapSet.new([
                  "cd08e31494f9531f560d64c695473da9",
                  "8ed066e87ae52cd04becca471a0b0892",
                  "b20b44b18b853ef29ab773e921b03422",
                  "334da95730484a993c6063e36bc90a47",
                  "ca0f3f4c08cbd372720beb1af7d2721f",
                  "b76d503360ae441d410a85a7f8d648ab",
                  "773906b0efdefa24a7f2b8eb6985bf37",
                  "400961c8161ba7661a7029d3f7e8bb95"
                ])

  @type fields :: {String.t(), [String.t()], [String.t()], [String.t()], [String.t()]}
  @type ja3_reference :: MapSet.t(String.t()) | [String.t()]

  @doc """
  Splits one tshark `-T fields` line into `{version, ciphers, ext_types,
  curves, point_fmts}`. Tokens are normalized to decimal (`0x0303` -> `771`),
  GREASE is stripped from ciphers/ext_types/curves, and empty groups become
  `[]`. Returns nil for malformed lines.
  """
  @spec parse_fields(String.t()) :: fields() | nil
  def parse_fields(line) when is_binary(line) do
    case String.split(line, ",") do
      [version, ciphers, ext_types, curves, point_fmts] ->
        with {:ok, version} <- version(version),
             {:ok, ciphers} <- group(ciphers),
             {:ok, ext_types} <- group(ext_types),
             {:ok, curves} <- group(curves),
             {:ok, point_fmts} <- group(point_fmts) do
          {version, strip_grease(ciphers), strip_grease(ext_types), strip_grease(curves),
           point_fmts}
        else
          _ -> nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Drops GREASE values (RFC 8701, `0x?a?a` — e.g. `0x0a0a`, `0x1a1a`) from a
  token list. Accepts hex- and decimal-spelled tokens; returns decimal.
  """
  @spec strip_grease([String.t()]) :: [String.t()]
  def strip_grease(tokens) do
    Enum.reject(tokens, fn token ->
      case to_int(token) do
        nil -> false
        value -> grease?(value)
      end
    end)
  end

  @doc """
  Renders parsed fields as the canonical JA3 string: fields joined with `,`,
  values within a field joined with `-`.
  """
  @spec ja3_string(fields()) :: String.t()
  def ja3_string({version, ciphers, ext_types, curves, point_fmts}) do
    Enum.join(
      [version, join(ciphers), join(ext_types), join(curves), join(point_fmts)],
      ","
    )
  end

  @doc """
  Hashes one `-T fields` line to its 32-hex lowercase JA3 MD5. Returns nil
  when the line does not parse.
  """
  @spec hash(String.t()) :: String.t() | nil
  def hash(line) do
    case parse_fields(line) do
      nil ->
        nil

      fields ->
        :crypto.hash(:md5, ja3_string(fields)) |> Base.encode16(case: :lower)
    end
  end

  @doc """
  L4 match confidence for one capture window, in `0.0..1.0`.

  Policy: max confidence across all ClientHellos in the window — `1.0` when
  any captured hash is in the reference, `0.0` otherwise (and for empty
  captures). A single non-browser hash does not dilute browser hashes on the
  same page load; conversely one browser hash marks the window as
  browser-like.
  """
  @spec match_score([String.t()], ja3_reference()) :: float()
  def match_score(hashes, reference \\ @browser_ja3s) when is_list(hashes) do
    if Enum.any?(hashes, &member?(reference, &1)), do: 1.0, else: 0.0
  end

  defp member?(%MapSet{} = reference, hash), do: MapSet.member?(reference, hash)
  defp member?(reference, hash) when is_list(reference), do: hash in reference

  # GREASE is 0x?a?a: both bytes equal and each low nibble is 0xa (RFC 8701).
  defp grease?(value), do: div(value, 256) == rem(value, 256) and rem(value, 16) == 10

  defp version(""), do: :error
  defp version(token), do: token |> to_int() |> render()

  defp group(""), do: {:ok, []}

  defp group(field) do
    field
    |> String.split("-")
    |> Enum.reduce_while({:ok, []}, fn token, {:ok, acc} ->
      case to_int(token) do
        nil -> {:halt, :error}
        value -> {:cont, {:ok, [Integer.to_string(value) | acc]}}
      end
    end)
    |> case do
      {:ok, tokens} -> {:ok, Enum.reverse(tokens)}
      :error -> :error
    end
  end

  defp to_int("0x" <> hex) do
    case Integer.parse(hex, 16) do
      {value, ""} -> value
      _ -> nil
    end
  end

  defp to_int(dec) do
    case Integer.parse(dec) do
      {value, ""} -> value
      _ -> nil
    end
  end

  defp render(nil), do: :error
  defp render(value), do: {:ok, Integer.to_string(value)}

  defp join([]), do: ""
  defp join(tokens), do: Enum.join(tokens, "-")
end
