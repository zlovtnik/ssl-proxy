defmodule TrafficAudit.TransportSelectorTest do
  use ExUnit.Case, async: true

  alias TrafficAudit.Domain.PcapFixture
  alias TrafficAudit.TransportSelector

  describe "transports/0" do
    test "audits the three wiring transports" do
      assert TransportSelector.transports() == [:obfs4, :wireguard, :tls_fronted]
    end
  end

  describe "select_best/2" do
    defp run_opts(sizes, gaps, confidence \\ 0.5) do
      pcap = PcapFixture.build(sizes, gaps)

      [
        capture_fn: fn _t, _o -> {:ok, pcap} end,
        dpi_fn: fn _ -> {:ok, %{confidence: confidence}} end,
        ja3_fn: fn _ -> {:ok, []} end
      ]
    end

    defp per_transport_opts(by_transport) do
      capture_fn = fn transport, _opts ->
        case Map.fetch(by_transport, transport) do
          {:ok, {sizes, gaps}} -> {:ok, PcapFixture.build(sizes, gaps)}
          :error -> {:error, :no_fixture}
        end
      end

      [
        capture_fn: capture_fn,
        dpi_fn: fn _ -> {:ok, %{confidence: 0.5}} end,
        ja3_fn: fn _ -> {:ok, []} end
      ]
    end

    test "picks the lowest composite among gate-passing candidates" do
      opts =
        per_transport_opts(%{
          obfs4: {PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps()},
          wireguard:
            {Enum.map(PcapFixture.reference_like_sizes(), &(&1 + 64)),
             PcapFixture.reference_like_gaps()},
          tls_fronted: {PcapFixture.degenerate_sizes(), PcapFixture.degenerate_gaps()}
        })

      assert {:ok, winner} = TransportSelector.select_best(TransportSelector.transports(), opts)
      assert winner.transport == :obfs4
      assert is_float(winner.composite_score)
    end

    test "hard-fails the whole selection when any candidate capture fails" do
      opts = [
        capture_fn: fn
          :obfs4, _o ->
            {:ok,
             PcapFixture.build(
               PcapFixture.reference_like_sizes(),
               PcapFixture.reference_like_gaps()
             )}

          :wireguard, _o ->
            {:error, :boom}

          :tls_fronted, _o ->
            {:error, :boom}
        end,
        dpi_fn: fn _ -> {:ok, %{confidence: 0.5}} end,
        ja3_fn: fn _ -> {:ok, []} end
      ]

      assert {:error, {:some_transports_failed, failures}} =
               TransportSelector.select_best(TransportSelector.transports(), opts)

      assert Enum.map(failures, &elem(&1, 0)) |> Enum.sort() == [:tls_fronted, :wireguard]
      assert Enum.all?(failures, &match?({_t, {:error, :boom}}, &1))
    end

    test "fails when every candidate fails" do
      opts = [capture_fn: fn _, _ -> {:error, :boom} end]

      assert {:error, {:some_transports_failed, failures}} =
               TransportSelector.select_best(TransportSelector.transports(), opts)

      assert length(failures) == 3
    end

    test "errors when no candidate passes the 0.20 gate" do
      opts = run_opts(PcapFixture.degenerate_sizes(), PcapFixture.degenerate_gaps())
      assert {:error, :no_passing_transport} = TransportSelector.select_best([:obfs4], opts)
    end

    test "applies per-transport weights: only tls_fronted is scored against L4" do
      opts =
        per_transport_opts(%{
          obfs4: {PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps()},
          wireguard: {PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps()},
          tls_fronted: {PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps()}
        })

      for transport <- [:obfs4, :wireguard] do
        assert {:ok, %{l3_flow: %{weights: weights}}} =
                 TransportSelector.select_best([transport], opts)

        assert Keyword.fetch!(weights, :l4) == 0.0
        assert_in_delta Enum.sum(Keyword.values(weights)), 1.0, 1.0e-12
      end

      assert {:ok, %{l3_flow: %{weights: weights}}} =
               TransportSelector.select_best([:tls_fronted], opts)

      refute Keyword.fetch!(weights, :l4) == 0.0
      assert_in_delta Enum.sum(Keyword.values(weights)), 1.0, 1.0e-12
    end

    test "replaces passed weights with the per-transport row" do
      opts = run_opts(PcapFixture.reference_like_sizes(), PcapFixture.reference_like_gaps())

      assert {:ok, %{l3_flow: %{weights: weights}}} =
               TransportSelector.select_best([:obfs4], Keyword.put(opts, :weights, l4: 0.5))

      assert Keyword.fetch!(weights, :l4) == 0.0
    end
  end
end
