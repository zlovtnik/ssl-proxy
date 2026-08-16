defmodule TrafficAudit.Domain.FlowStats do
  @moduledoc """
  Pure, side-effect-free scoring primitives for a single transport candidate.

  No `Port`, no `System.cmd`, no `Ecto.Repo` — only math over packet lists.
  Histograms are built with fixed bucket widths so they are deterministic and
  comparable across runs:

      size     -> 64-byte buckets (quantized byte counts)
      timing   -> 10 ms buckets (quantized inter-packet gaps)

  Divergence is Jensen-Shannon (base 2), bounded [0, 1] and symmetric: 0.0 means
  the candidate is statistically indistinguishable from the reference, 1.0 means
  maximally disjoint.
  """

  alias TrafficAudit.Domain.Pcap
  alias TrafficAudit.Domain.Types

  @size_bucket 64
  @timing_bucket_ms 10

  # Fixed L1-L4 weights, kept next to the scoring math. Sum to 1.0. Overridable
  # per call for sensitivity analysis only — there is no runtime config path.
  @weights [l1: 0.15, l2: 0.25, l3_size: 0.30, l3_timing: 0.30, l4: 0.0]

  @type packet :: Types.Packet.t()
  @type score :: Types.Score.t()

  @doc """
  Builds a packet-size histogram (64-byte buckets) from a packet stream.
  """
  @spec size_histogram([packet]) :: Types.Histogram.t()
  def size_histogram(packets) do
    buckets =
      Enum.reduce(packets, %{}, fn %Types.Packet{size: size}, acc ->
        bucket = quantize(size, @size_bucket)
        Map.update(acc, bucket, 1, &(&1 + 1))
      end)

    %Types.Histogram{buckets: buckets}
  end

  @doc """
  Builds an inter-packet timing histogram (10 ms buckets) from a packet stream.
  Direction is ignored — only arrival ordering matters.
  """
  @spec timing_histogram([packet]) :: Types.Histogram.t()
  def timing_histogram(packets) do
    buckets =
      packets
      |> Enum.sort_by(& &1.ts)
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.reduce(%{}, fn [a, b], acc ->
        gap_ms = max(0.0, (b.ts - a.ts) * 1000.0)
        bucket = quantize(gap_ms, @timing_bucket_ms)
        Map.update(acc, bucket, 1, &(&1 + 1))
      end)

    %Types.Histogram{buckets: buckets}
  end

  @doc """
  Jensen-Shannon divergence (base 2) of two histograms, bounded [0, 1] and
  symmetric. Returns 0.0 when both histograms are empty.
  """
  @spec js_divergence(Types.Histogram.t(), Types.Histogram.t()) :: float()
  def js_divergence(%Types.Histogram{buckets: p}, %Types.Histogram{buckets: q}) do
    total_p = Enum.reduce(p, 0, fn {_, c}, acc -> acc + c end)
    total_q = Enum.reduce(q, 0, fn {_, c}, acc -> acc + c end)

    keys = MapSet.union(MapSet.new(Map.keys(p)), MapSet.new(Map.keys(q)))

    raw =
      Enum.reduce(keys, 0.0, fn key, acc ->
        p_k = if total_p > 0, do: Map.get(p, key, 0) / total_p, else: 0.0
        q_k = if total_q > 0, do: Map.get(q, key, 0) / total_q, else: 0.0
        m_k = (p_k + q_k) / 2.0
        acc + kl_term(p_k, m_k) + kl_term(q_k, m_k)
      end) / 2.0

    # Base-2 JSD is theoretically in [0, 1]; clamp for float safety.
    between(0.0, raw, 1.0)
  end

  @doc """
  A canned "normal HTTPS" reference distribution. This is *reference data*, not
  IO: it is pure and hardcoded so the gate has a deterministic baseline without a
  corpus pipeline. Refresh cadence for a live baseline is an open item.
  """
  @spec reference_https() :: {Types.Histogram.t(), Types.Histogram.t()}
  def reference_https do
    # 64-byte buckets: real HTTPS bulk-transfer skews toward 1400+ bytes.
    size_ref = %{
      0 => 2,
      64 => 3,
      128 => 2,
      256 => 4,
      512 => 6,
      1408 => 11,
      1472 => 5
    }

    # 10 ms buckets: typical HTTPS pacing clusters at 0-80 ms.
    timing_ref = %{
      0 => 7,
      10 => 6,
      20 => 4,
      30 => 3,
      40 => 2,
      60 => 2,
      80 => 2
    }

    {to_hist(size_ref), to_hist(timing_ref)}
  end

  @doc """
  Blends the L2 DPI confidence, the L3 flow divergence, and the L4 JA3 match
  into one composite score in [0, 1].

  Pure: no IO, no config reads — the weights are fixed in this module.

  `flow` is a `Types.Score` or any map carrying `:l3_size_divergence` and
  `:l3_timing_divergence`. `l4` may be a pre-clamped float, a list of JA3
  fingerprints (no match information -> 0.0), or nil.
  """
  @spec composite(map() | nil, Types.Score.t() | map(), float() | list() | nil, keyword()) ::
          float()
  def composite(l2, flow, l4, weights \\ @weights) do
    w_l1 = Keyword.get(weights, :l1, 0.0)
    w_l2 = Keyword.get(weights, :l2, 0.0)
    w_size = Keyword.get(weights, :l3_size, 0.0)
    w_timing = Keyword.get(weights, :l3_timing, 0.0)
    w_l4 = Keyword.get(weights, :l4, 0.0)

    between(
      0.0,
      w_l1 * flow_l1(flow) +
        w_l2 * l2_score(l2) +
        w_size * divergence_of(flow, :l3_size_divergence) +
        w_timing * divergence_of(flow, :l3_timing_divergence) +
        w_l4 * l4_score(l4),
      1.0
    )
  end

  @doc """
  Scores one transport's captured pcap against a reference distribution.

  Parses the pcap bytes (purely) and delegates to `score_from_packets/3`.

  ## Options — see `score_from_packets/3`.
  """
  @spec score(iodata(), atom(), keyword()) :: score()
  def score(pcap, transport, opts \\ []) do
    pcap
    |> Pcap.parse()
    |> score_from_packets(transport, opts)
  end

  @doc """
  Scores a pre-parsed packet list against a reference distribution.

  ## Options
    - `:reference`       — `{size_hist, timing_hist}` baseline (default: `reference_https/0`)
    - `:threshold`       — hard JS-divergence gate (default `0.20`)
    - `:weights`         — `[l1:, l2:, l3_size:, l3_timing:, l4:]` summing to 1.0
    - `:commit_sha`      — recorded on the resulting Score
    - `:l1`, `:l2`, `:l4_ja3_match` — upstream layer values wired in by the recipe

  `passed?` is the hard gate: `max(size_div, timing_div) <= threshold`.
  `composite` is the weighted sum across L1-L4 + L3 divergence, clamped [0, 1].
  """
  @spec score_from_packets([packet], atom(), keyword()) :: score()
  def score_from_packets(packets, transport, opts \\ []) do
    {size_ref, timing_ref} = Keyword.get(opts, :reference, reference_https())
    threshold = Keyword.get(opts, :threshold, 0.20)
    weights = Keyword.get(opts, :weights, @weights)

    size_hist = size_histogram(packets)
    timing_hist = timing_histogram(packets)
    size_div = js_divergence(size_hist, size_ref)
    timing_div = js_divergence(timing_hist, timing_ref)
    worst = max(size_div, timing_div)

    l1 = Keyword.get(opts, :l1, 0.0) || 0.0
    l2 = Keyword.get(opts, :l2, nil)
    l4 = Keyword.get(opts, :l4_ja3_match, 0.0) || 0.0

    flow = %{l1: l1, l3_size_divergence: size_div, l3_timing_divergence: timing_div}

    composite = composite(l2, flow, l4, weights)

    %Types.Score{
      transport: transport,
      l1: Keyword.get(opts, :l1),
      l2: l2,
      l3_size_divergence: size_div,
      l3_timing_divergence: timing_div,
      l4_ja3_match: Keyword.get(opts, :l4_ja3_match),
      composite: composite,
      passed?: worst <= threshold,
      commit_sha: Keyword.get(opts, :commit_sha),
      weights: weights
    }
  end

  # ---------------------------------------------------------------------------
  # Helpers (private, pure)
  # ---------------------------------------------------------------------------

  @spec quantize(number(), pos_integer()) :: integer()
  defp quantize(value, _width) when value < 0, do: 0
  defp quantize(value, width) when is_integer(value), do: floor(value / width) * width
  defp quantize(value, width) when is_float(value), do: floor(value / width) * width

  @spec to_hist(map()) :: Types.Histogram.t()
  defp to_hist(map), do: %Types.Histogram{buckets: map}

  # L2 DPI confidence -> numeric in [0,1]: 1.0 (trusted) down to 0.0 (untrusted).
  @spec l2_score(map() | nil) :: float()
  defp l2_score(nil), do: 0.0
  defp l2_score(%{confidence: c}) when is_float(c), do: between(0.0, c, 1.0)
  defp l2_score(%{confidence: c}) when is_integer(c), do: between(0.0, c / 100.0, 1.0)
  defp l2_score(_), do: 0.0

  # L4 JA3 match -> numeric in [0,1]. A raw fingerprint list carries no match
  # confidence, so it scores 0.0; callers that compare against a browser
  # reference pass a pre-computed float instead.
  @spec l4_score(float() | list() | nil) :: float()
  defp l4_score(nil), do: 0.0
  defp l4_score(n) when is_float(n), do: between(0.0, n, 1.0)
  defp l4_score(n) when is_integer(n), do: between(0.0, n / 100.0, 1.0)
  defp l4_score(_), do: 0.0

  @spec flow_l1(Types.Score.t() | map()) :: float()
  defp flow_l1(%{l1: l1}), do: l1 || 0.0
  defp flow_l1(_), do: 0.0

  @spec divergence_of(Types.Score.t() | map(), atom()) :: float()
  defp divergence_of(flow, key) when is_map(flow) do
    case Map.get(flow, key) do
      nil -> 0.0
      n when is_number(n) -> n
      %Decimal{} = d -> Decimal.to_float(d)
    end
  end

  @spec between(float(), float(), float()) :: float()
  defp between(lo, x, hi), do: max(lo, min(hi, x))

  # KL divergence term in base 2; 0 when the P mass for a bin is 0
  # (convention 0*log(0) = 0). The caller guarantees m_k > 0 for every union key.
  @spec kl_term(float(), float()) :: float()
  defp kl_term(p, _m) when p == 0.0, do: 0.0
  defp kl_term(p, m), do: p * :math.log2(p / m)
end
