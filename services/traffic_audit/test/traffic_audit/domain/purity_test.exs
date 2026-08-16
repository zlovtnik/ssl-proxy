defmodule TrafficAudit.Domain.PurityTest do
  @moduledoc """
  L0 purity guard: `domain/` must import zero IO primitives.

  Mirrors the repo's `make dependency-boundaries` check for the Elixir domain
  layer. String literals and comments are stripped before scanning so the guard
  only trips on real code references (not prose in a `@moduledoc`).
  """
  use ExUnit.Case, async: true

  @forbidden ~r/(Port\.|System\.|Ecto\.Repo|File\.|:os\.cmd|HTTPoison|Finch|Req|Mint)/

  @domain_dir File.cwd!() |> Path.join("lib/traffic_audit/domain")

  test "domain/ contains no IO primitives" do
    files = Path.wildcard(Path.join(@domain_dir, "**/*.ex"))

    refute files == [], "no domain files found at #{@domain_dir}"

    offenders =
      Enum.flat_map(files, fn file ->
        lines = file |> File.read!() |> strip_strings_and_comments() |> String.split("\n")

        Enum.with_index(lines)
        |> Enum.filter(fn {line, _} -> String.match?(line, @forbidden) end)
        |> Enum.map(fn {line, idx} ->
          {Path.relative_to_cwd(file), idx + 1, line |> String.trim()}
        end)
      end)

    assert offenders == [],
           "domain/ must be pure (no Port/System/Ecto.Repo/File/...) but found:\n" <>
             Enum.map_join(offenders, "\n", fn {file, line, text} ->
               "  #{file}:#{line}: #{text}"
             end)
  end

  # Strip heredocs, then double- and single-quoted string literals, then line
  # comments. Order matters: strings first (so `#` inside a string is kept
  # inert), comments last.
  defp strip_strings_and_comments(src) do
    src
    |> String.replace(~r/"""[\s\S]*?"""/, "", global: true)
    |> String.replace(~r/"(?:\\.|[^"\\])*"/, "", global: true)
    |> String.replace(~r/'(?:\\.|[^'\\])*'/, "", global: true)
    |> String.replace(~r/#.*$/, "", global: true)
  end
end
