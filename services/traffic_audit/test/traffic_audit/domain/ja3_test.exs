defmodule TrafficAudit.Domain.Ja3Test do
  use ExUnit.Case, async: true
  use ExUnitProperties, async: true

  alias TrafficAudit.Domain.Ja3

  @chrome120 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

  describe "parse_fields/1" do
    test "splits a full ClientHello field line" do
      assert Ja3.parse_fields("771,4865-4866-4867,0-23-65281-10,29-23-24,0") ==
               {"771", ["4865", "4866", "4867"], ["0", "23", "65281", "10"], ["29", "23", "24"],
                ["0"]}
    end

    test "normalizes a hex version token to decimal" do
      assert Ja3.parse_fields("0x0303,4865,0,29,0") ==
               {"771", ["4865"], ["0"], ["29"], ["0"]}
    end

    test "empty groups become empty lists" do
      assert Ja3.parse_fields("769,4-5-10-9-100-98-3-6-19-18-99,,,") ==
               {"769", ["4", "5", "10", "9", "100", "98", "3", "6", "19", "18", "99"], [], [], []}
    end

    test "returns nil for a malformed line" do
      assert Ja3.parse_fields("771,4865") == nil
      assert Ja3.parse_fields("nope,4865,0,29,0") == nil
    end
  end

  describe "strip_grease/1" do
    test "drops hex-spelled GREASE values" do
      assert Ja3.strip_grease(["0x0a0a", "4865", "0x1a1a", "0xfafa"]) == ["4865"]
    end

    test "drops decimal-spelled GREASE values" do
      assert Ja3.strip_grease(["2570", "4865", "6682", "64250"]) == ["4865"]
    end

    test "keeps non-GREASE values that share a low nibble" do
      assert Ja3.strip_grease(["10", "0x0a1a", "2569"]) == ["10", "0x0a1a", "2569"]
    end
  end

  describe "golden JA3 vectors" do
    test "salesforce README vector with all fields" do
      assert Ja3.hash("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0") ==
               "ada70206e40642a3e4461f35503241d5"
    end

    test "salesforce README vector with empty extension fields" do
      assert Ja3.hash("769,4-5-10-9-100-98-3-6-19-18-99,,,") ==
               "de350869b8c85de67a350c8d186f11e6"
    end

    test "Chrome 120 vector" do
      assert Ja3.hash(@chrome120) == "cd08e31494f9531f560d64c695473da9"
    end

    test "GREASE insertion is hash-invariant" do
      greased =
        "771,4865-2570-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-6682-35-16-5-13-18-51-45-43-27-17513-21,29-10794-23-24,0"

      assert Ja3.hash(greased) == Ja3.hash(@chrome120)
      assert Ja3.hash(greased) == "cd08e31494f9531f560d64c695473da9"
    end

    test "returns nil for a line that does not parse" do
      assert Ja3.hash("garbage") == nil
    end
  end

  describe "match_score/2" do
    @ref MapSet.new(["cd08e31494f9531f560d64c695473da9"])

    test "scores 1.0 when any captured hash is in the reference" do
      assert Ja3.match_score(["cd08e31494f9531f560d64c695473da9"], @ref) == 1.0

      assert Ja3.match_score(
               ["ffffffffffffffffffffffffffffffff", "cd08e31494f9531f560d64c695473da9"],
               @ref
             ) == 1.0
    end

    test "scores 0.0 when nothing matches or the capture is empty" do
      assert Ja3.match_score(["ffffffffffffffffffffffffffffffff"], @ref) == 0.0
      assert Ja3.match_score([], @ref) == 0.0
    end

    test "accepts a plain list as the reference" do
      assert Ja3.match_score(
               ["cd08e31494f9531f560d64c695473da9"],
               ["cd08e31494f9531f560d64c695473da9"]
             ) == 1.0
    end

    test "default reference matches the verified browser hashes" do
      assert Ja3.match_score(["cd08e31494f9531f560d64c695473da9"]) == 1.0
      assert Ja3.match_score(["773906b0efdefa24a7f2b8eb6985bf37"]) == 1.0
      assert Ja3.match_score(["00000000000000000000000000000000"]) == 0.0
    end
  end

  property "GREASE-only list fields always strip to empty" do
    check all(tokens <- list_of(one_of([grease_hex(), grease_decimal()]))) do
      field = Enum.join(tokens, "-")

      assert Ja3.parse_fields("771,#{field},#{field},#{field},0") ==
               {"771", [], [], [], ["0"]}
    end
  end

  defp grease_hex do
    member_of(
      Enum.map(0..15, fn n -> "0x#{Integer.to_string(n, 16)}a#{Integer.to_string(n, 16)}a" end)
    )
  end

  defp grease_decimal do
    member_of(Enum.map(0..15, fn n -> Integer.to_string(257 * (16 * n + 10)) end))
  end
end
