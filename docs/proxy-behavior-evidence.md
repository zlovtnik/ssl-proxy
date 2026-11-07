# Bounded proxy behavioral evidence

Octopus extends the [lifecycle preparation](proxy-flow-lifecycle.md#runtime-preparation)
with B05-B09 from the [workmap](../advisor-plans/002-proxy-rag-ml-workmap.md#stage-6-build-bounded-behavioral-evidence).
These projections describe retained observations and candidate patterns. G8
deployment calibration and production activation remain open.

## Publication and history

The existing expiring, attested `proxy_behavior_policy` admits preparation.
No policy row is installed automatically. All outputs share the source
snapshot, processor fence, output cursor, calculation version and revision
sequence. Fingerprint changes replace evidence; exact replay preserves the
revision. Removed sources, unsupported scopes, overflow and expired policies
retire bounded pages. Readers must check `proxy_behavior_status` before treating
a projection set as complete.

The [additive schema](../sql/postgres/atheros_search/01_tables/023_proxy_behavior_scopes.sql)
adds `proxy_destination_history`, `proxy_device_window` and
`proxy_attribution_window`. Octopus writes these tables; Search can read them.
The source bound remains at most 10,000 rows and a seven-day lookback, with
pairing context. The configured `max_windows` now bounds the combined host,
registration, attribution and destination outputs, at most 168. A source or
output overflow fails closed rather than publishing a partial positive claim.
No Go reader, API or alert contract changes are part of this stage.

First observation and last observation use event time and event ID within
`retained_history_start` and `retained_history_end`. Late earlier evidence
corrects the first sighting; duplicates count once. Rarity is the fraction of
observations of a destination among observations with supported endpoints in
the same deployment, registration epoch or process peer scope. The unit and
denominator accompany the value. Unsupported endpoints do not enter this
denominator; deployment attribution coverage still includes them.

`new_to_retained_scope` describes the first retained sighting in a window.
`new_to_scope_ever` and domain registration time are unavailable. Every history
is explicitly left-censored; contiguous collection within the retained bounds
does not establish deployment inception or domain age. History completeness
requires the coverage and conflict attestations to span the retained bounds.

## Attribution coverage

The [producer identity evidence](../src/identity.rs) supplies registration
claims and rotating peer references. A registration scope requires supported
evidence versions, a registered device identifier, a supported method, an
explicit process peer reference, and a valid half-open claim interval covering
the observation. The mapping revision must equal the interval start. Its
opaque key includes deployment, registration, peer and interval. Token and peer
claims describe registrations; they do not prove physical device ownership.

Overlapping claims for different registrations on one peer conservatively
invalidate that peer's registration scopes. Conflicting source payloads cannot
create claims or mapping changes. Shared addresses alone cannot establish a
scope. Process restart, key rotation or a changed claim epoch produces a
separate scope. Device windows overlap only their validated epoch; partially
covered windows report `attribution_interval_limited`.

Each deployment attribution window reconciles unique supported event IDs into
supported registration, scoped unattributed peer and unknown. Their sum equals
the denominator. Conflicting IDs are excluded and counted separately. Method
and validity counts, unavailable rates, mapping changes and supporting event
IDs remain explicit. Empty denominators produce null rates. Host-window
coverage uses that host's supported observations, while deployment coverage
also includes unavailable endpoint observations.

## Polling, transfers and policy friction

Polling evaluates unique HTTP observation times and validated flow opening
times as separate series. Open and close observations never double count a
flow. It reports interval median, median absolute deviation, relative
dispersion and twelve active time bins. The provisional candidate rule needs
six samples, three active bins and relative dispersion at most 0.1. Collection
or coalescing uncertainty prevents a positive candidate disposition for that
series. Flow starts require coverage for the pairing horizon before and after
the window, and registration-scoped flows require the claim to remain valid
through the end of that horizon. Ordinary telemetry and update polling can
satisfy this rule. Periodicity establishes no confirmed threat. Suppression
counters describe prior collection windows, not
application attempts.

Transfer evidence uses validated terminal successful-write measurements only.
Partial, estimated, legacy and unavailable bytes cannot enter confirmed
totals or history. Upload, upload/download ratio and connection elapsed
duration have separate median/MAD profiles. Historical samples precede the
current window, with flow references and actual sample bounds retained. Six
prior measured samples are required. A zero download produces an unavailable
ratio with `zero_download`; it never creates infinity. The provisional upward
deviation rule uses six robust scales with a documented scale floor. Novelty
and insufficient history remain separate evidence. An anomaly candidate does
not establish exfiltration.

Policy friction reports repeated block/error observations, related allowed
observations and a timeline of at most 32 supporting IDs/times/outcomes in the
same scope and half-open window. The timeline prioritizes up to 24 friction
observations and fills remaining slots with allowed observations; omitted
rows are counted. Retry counts and application-failure causality remain
unavailable. Coalescing and final unreported windows can hide observations.

The pure [processor fixtures](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/)
in `ProxyBehaviorScopeSuite` and `ProxyBehaviorStatisticsSuite`
cover benign and irregular controls, censoring, late/replayed evidence,
overlapping claims, rotation, measurement exclusions, zero downloads and
history leakage. Canonical PostgreSQL tests cover persistence and retirement.
These checks establish deterministic development behavior. They do not supply
reviewed labels, detector precision, alert rates or production scan budgets.

## Follow-on intelligence evidence

Calculation `proxy-behavior-v3` adds structured fields to the existing host and
registration windows, under the same source snapshot, fence, policy expiry and
retirement path. Semantic text stays unchanged. No runtime policy is installed.
The [follow-on workmap](../advisor-plans/002-proxy-rag-ml-workmap.md#follow-on-intelligence-backlog)
distinguishes these local implementations from remaining calibration gates.

- `clienthello_drift` partitions `ja3_lite` and first-offered ALPN profiles by
  supported producer parser revision. Six available observations in each slice,
  a supported registration epoch and attested current/history coverage are
  required for a drift candidate. Tunnel closes cannot duplicate the opening
  sample. Missing TLS/ALPN, parser changes and insufficient history stay explicit.
  A software update can produce the same candidate; neither ownership nor threat
  confidence follows. ALPN is the first offered value, not the full offer list.
- `destination_infrastructure` separates selected connected-socket IPs from
  resolver candidates on unique unblocked tunnel openings. Strict numeric
  address normalization never uses client `peer_ip` or performs DNS. Address-set
  differences describe retained observations; CDN rotation, load balancing and
  shared infrastructure remain benign explanations. ASN is explicitly unavailable:
  no enrichment dataset, network lookup or cache is configured. Any future cache
  requires provenance, version, refresh/expiry and outage verification first.
- `domain_lexical` describes normalized ASCII DNS labels with length, entropy
  and digit fraction, using the existing pinned IDNA/PSL normalization. It compares
  distinct subdomains using all supported rows for the same registrable domain
  within the deployment or registration epoch. IP literals, sanitized/invalid
  names and unavailable domains cannot create lexical evidence. Protected-domain
  similarity is unavailable without a supplied list. No anomaly threshold is
  installed, so candidate and false-positive rate are null with explicit reasons.
  CDN and telemetry controls are fixtures, not reviewed precision measurements.

Baselines precede the half-open current window and remain left-censored.
Registration rotation cannot import another epoch's history or domain context.
Exact counts accompany capped profiles, host lists and source references with
omission counts. A source/address bound violation yields unavailable evidence.
The processor fixtures `ProxyClientHelloDriftSuite`,
`ProxyDestinationInfrastructureSuite`, `ProxyDomainLexicalSuite` and
`ProxyFollowOnIntegrationSuite` cover deterministic replay, scope, missing inputs,
benign controls, future-history exclusion and bounds. Canonical persistence
checks verify publication, stable replay and retirement on policy expiry.

F04 remains gated by B11 compatible similarity, correction/expiry invalidation
and recall acceptance. F05 remains gated by B12 versioned signal/alert derivation;
there is no local feed dataset or alert contract to correlate or retract yet.
Neither capability is represented as implemented by these descriptive fields.

## Additive TCP JA4 evidence

The [producer TLS parser](../src/tunnel/tls.rs) now publishes a separate
`tls_evidence.ja4_evidence` object with version `proxy-ja4-v1`, transport, source,
specification revision, availability and fingerprint. The independent
[JA4 implementation](../src/tunnel/ja4.rs) reads complete raw TCP ClientHello
inputs: protocol/supported versions, cipher list, extension kinds, SNI presence,
first ALPN bytes and wire-order signature algorithms. It does not reconstruct
JA4 from `ja3_lite`; existing fingerprint and ALPN fields retain their semantics.

The implementation pins the
[FoxIO TLS-client specification](https://github.com/FoxIO-LLC/ja4/blob/c6469a7b0dbf8fe963810162429fbfd9d1acc4d5/technical_details/JA4.md)
and its
[BSD-3-Clause license](https://github.com/FoxIO-LLC/ja4/blob/c6469a7b0dbf8fe963810162429fbfd9d1acc4d5/LICENSE-JA4).
It does not implement other JA4+ methods. Unsupported, incomplete, malformed or
over-budget handshakes publish a null fingerprint and an unavailable reason;
the producer's existing 8 KiB/500 ms inspection bound remains. QUIC and DTLS
fingerprinting are unavailable. Conformance fixtures exercise the pinned example,
GREASE, signature order, ALPN bytes, invalid vectors and audit propagation.
No downstream JA4 detector or threat/identity inference is added.

## Local verification record

On 2026-11-07, the Docker-enabled Octopus `sbt test` run passed 667 tests,
including all 74 canonical persistence cases; the opt-in live hydration probe
was skipped. A final focused rerun after strengthening scope/publication
assertions passed 39 tests, including the four new follow-on integration cases,
all three evidence suites and documentation/feature contracts. The Rust library
suite passed 227 tests, and final audit propagation checks passed four tests.
Documentation, dependency-boundary and whitespace checks passed. Strict Rust
Clippy remains blocked by the existing `type_complexity` diagnostic in
`src/state_sections/models.rs`; the run allowing only that lint passed.
These commands populated ignored local build/test caches. No production
deployment, schema application or runtime policy admission was performed.

On 2026-11-06, `OCTOPUS_REQUIRE_DOCKER=true` with the local Docker socket and
`sbt test` in `services/octopus` passed 635 tests. The only skipped test was the
explicitly opt-in live hydration probe; all 74 canonical persistence tests ran.
The new scope/statistics suites contain 22 deterministic tests. Producer
`cargo test -p ssl-proxy --lib` passed 223 tests; `cargo test -p sync-plane`
passed 14 tests. Dependency boundaries passed.

The isolated provisioning-executor integration passed fresh install, trusted
upgrade, replay, actual grants, checksum drift and ownership checks. The
expanded migration/audit harness passed 37 regressions, including populated
upgrade budgets and concurrent-writer behavior. Six executor unit tests and
22 production-manifest tests passed. Schema-contract, GitOps, documentation
and whitespace checks passed. Build/test commands populated local build caches;
no production DDL, image promotion or runtime policy activation was performed.
