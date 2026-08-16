# TrafficAudit

A per-commit CI gate for the ISP-visible fingerprint of `ssl-proxy`'s
obfuscation transport (`obfs4` / plain WireGuard / TLS-fronted).

It runs a plain `with`-chained pipeline against each candidate transport,
scores packet-size and timing divergence against a "normal HTTPS" reference
(Jensen-Shannon), and selects the best transport. Scores are persisted via
`TrafficAudit.Persistence` — log-only today, with the Ecto Repo + schema in
tree, one config flag from on-boarding TiDB.

## Layers (flat — no DSL in the runtime pipeline)

```
domain/             pure math (JS divergence, histograms) — no IO, no exceptions
io/                 thin IO wrappers — one function each
pipeline.ex         `with`-chain composing domain + io
transport_selector.ex  runs the pipeline per candidate, picks the winner
persistence.ex      single save call site (log or Repo)
audit_supervisor.ex composition root
cli.ex              escript entrypoint
```

The runtime pipeline is plain `with`-chained code: no custom control-flow
types, no macros — a dev who knows `with` and `{:ok, _}/{:error, _}` can read
every runtime file. (This claim covers the runtime pipeline only; the
`test/support` fixture builders and the fixture-generation script are
standalone tooling, not part of that pipeline.)

## Running

```sh
# One-shot gate for a commit (default: live capture via tcpdump)
mix escript.build
./traffic-audit run COMMIT_SHA

# Deterministic, unprivileged fixture mode: score the checked-in fixture pcaps
TRAFFIC_AUDIT_CAPTURE_MODE=fixture ./traffic-audit run COMMIT_SHA

# Regenerate the fixture pcaps (committed artifacts)
mix run scripts/generate_fixtures.exs
```

Fixture mode still needs `ndpiReader` for the DPI step, so the PR gate in CI
runs the fixture mode **inside the built runtime image**:

```sh
docker build -t traffic-audit -f services/traffic_audit/Dockerfile services/traffic_audit
docker run --rm -e TRAFFIC_AUDIT_CAPTURE_MODE=fixture traffic-audit run COMMIT_SHA
```

Live capture requires NET_RAW/NET_ADMIN on the runner and uses
`timeout -s INT <s> tcpdump -i <iface> -w -` (tcpdump's own `-G` needs a
strftime pattern in the `-w` filename, so the duration is enforced by
`timeout`).

## Layout

- `lib/traffic_audit/domain/` — pure scoring primitives (the only thing you
  touch to add a check). `test/traffic_audit/domain/purity_test.exs` enforces
  zero `Port`/`System`/`Ecto.Repo` imports.
- `lib/traffic_audit/io/` — `capture.ex` (tcpdump / fixture), `dpi.ex`
  (ndpiReader), `ja3.ex` (tshark), all sharing `shell.ex`.
- `lib/traffic_audit/pipeline.ex` — the whole per-transport "recipe" in one
  readable function.
- `lib/traffic_audit/schemas/transport_score.ex` — Ecto schema (dormant until
  `:persistence, :repo` is enabled and the TiDB governance surface exists).
- `priv/fixtures/` — deterministic pcaps for unprivileged CI.
- `scripts/generate_fixtures.exs` — regenerates those fixtures.

JA3: `Io.Ja3` runs `tshark -T fields` raw ClientHello extraction (Wireshark
4.x removed the old `-z ja3,tree` statistics argument) and reduces each
ClientHello line to its JA3 MD5 in `Domain.Ja3`, normalizing Wireshark's hex
version token and stripping RFC 8701 GREASE so hashes match canonical JA3
databases. The L4 score is a match against a static known-browser reference
(`Domain.Ja3.match_score/2`, 0.0/1.0 policy) and only `tls_fronted` is scored
against it — obfs4 and wireguard move that weight share onto L2/L3. The
runtime image ships tshark; dev machines without it degrade to "no
fingerprints" (L4 weight 0.0).

DPI: `Io.Dpi` runs `ndpiReader -i FILE` and `Domain.DpiSummary` parses the
printed statistics into the version, packet/flow counts, the per-protocol
breakdown, and a classification confidence — the share of flows nDPI did not
leave Unknown or Speculative — that becomes the L2 score. The Debian build of
ndpiReader 4.2 has no JSON flow dump (`-J` prints help and exits), so parsing
is anchored on the printed headers; the raw banner is not carried into
results.

This project is part of the `ssl-proxy` monorepo.