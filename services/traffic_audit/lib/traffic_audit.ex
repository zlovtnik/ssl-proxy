defmodule TrafficAudit do
  @moduledoc """
  `traffic_audit` — a per-commit CI gate that scores the ISP-visible fingerprint
  of `ssl-proxy`'s obfuscation transport.

  It runs a plain `with`-chained pipeline against the wiring transports `obfs4` /
  plain WireGuard / TLS-fronted, scores packet-size and timing divergence against
  a "normal HTTPS" reference, and selects the best transport. Scores are
  persisted via `TrafficAudit.Persistence` (log-only today; the Ecto Repo and
  `TransportScore` schema are in tree, one config flag from on-boarding TiDB).

  ## Layers

      domain/             pure math (JS divergence, histograms) — no IO
      io/                 thin IO wrappers — one function each
      pipeline.ex         `with`-chain composing domain + io
      transport_selector.ex  runs the pipeline per candidate, picks the winner
      persistence.ex      single save call site (log or Repo)
      audit_supervisor.ex composition root
      cli.ex              escript entrypoint

  No custom control-flow types, no macros — `with` and `{:ok, _}/{:error, _}`
  is the entire abstraction.
  """

  @doc """
  Runs the transport-scoring audit for `commit_sha` and returns
  `{:ok, result}` (the selected winner map) or `{:error, reason}`.

  This is a thin facade over `TrafficAudit.AuditSupervisor`, the single
  composition root.
  """
  @spec run(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def run(commit_sha, opts \\ []) do
    TrafficAudit.AuditSupervisor.run(commit_sha, opts)
  end
end
