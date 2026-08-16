defmodule TrafficAudit.Domain.Types do
  @moduledoc """
  Canonical immutable value types for the pure domain layer (L0).

  These are plain Elixir structs — no IO, no `Port`, no `System.cmd`, no
  `Ecto.Repo`. The purity checker in
  `test/traffic_audit/domain/purity_test.exs` enforces that `domain/` imports
  none of those.
  """

  @typedoc "One captured packet: byte size, flow direction, timestamp in seconds."
  @type packet :: %__MODULE__.Packet{}

  defmodule Packet do
    @moduledoc "A single captured packet observed on the wire."
    @enforce_keys [:size, :direction, :ts]
    defstruct [:size, :direction, :ts]

    @type t :: %__MODULE__{
            size: non_neg_integer(),
            direction: :in | :out,
            ts: float()
          }
  end

  defmodule Histogram do
    @moduledoc "A count histogram over integer buckets."
    @enforce_keys [:buckets]
    defstruct buckets: %{}
    @type t :: %__MODULE__{buckets: %{integer() => non_neg_integer()}}
  end

  defmodule Score do
    @moduledoc """
    Result of scoring one transport candidate for one commit.

    `l1`-`l4` are the per-layer fingerprints; `composite` is the weighted sum;
    `passed?` is the hard-threshold gate on L3 (worst-of size/timing divergence).
    """
    @derive {
      Jason.Encoder,
      only: [:transport, :l1, :l3_size_divergence, :l3_timing_divergence, :l4_ja3_match, :composite, :passed?, :commit_sha]
    }
    @enforce_keys [:transport, :l3_size_divergence, :l3_timing_divergence, :composite, :passed?]
    defstruct [
      :transport,
      :l1,
      :l2,
      :l3_size_divergence,
      :l3_timing_divergence,
      :l4_ja3_match,
      :composite,
      :passed?,
      :commit_sha,
      :weights
    ]

    @type t :: %__MODULE__{
            transport: atom(),
            l1: float() | nil,
            l2: map() | nil,
            l3_size_divergence: float(),
            l3_timing_divergence: float(),
            l4_ja3_match: float() | nil,
            composite: float(),
            passed?: boolean(),
            commit_sha: String.t() | nil,
            weights: keyword() | nil
          }
  end
end
