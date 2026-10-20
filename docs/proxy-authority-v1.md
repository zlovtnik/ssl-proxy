# Proxy authority normalization v1

Contract: [shared corpus](../sql/postgres/contracts/fixtures/proxy-authority-v1.json).
Implementations: `ProxyAuthority.scala` in the [Scala preparation package](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/)
and `authority.go` in the [Go queryscope package](../apps/integration-console/atheros-search/internal/queryscope/).
These pure APIs do not change existing persisted documents, routing, source IDs,
substring host filtering, or embeddings. Persistence and additive API wiring
remain stages 3, 4 and 7 of the [workmap](../advisor-plans/002-proxy-rag-ml-workmap.md).

## Fields and bounds

| Field | Meaning |
| --- | --- |
| `authority_raw` | Original authority input, including explicitly observed port; null for unsafe encoding, controls or input over 1024 UTF-8 bytes |
| `host_raw` | Extracted host spelling, without brackets or port; null when parsing stopped before extraction |
| `host_normalized` | Lowercase ASCII DNS name without its final root dot, strict IPv4, or compressed lowercase IPv6; null unless valid |
| `port` | Explicit decimal port 1..65535; absent stays null, including absent default ports |
| `authority_normalized` | Normalized host with IPv6 brackets and explicit port when present |
| `registrable_domain` | PSL eTLD+1 including private suffix policy; null for IPs and public suffixes themselves |
| `normalization_version` | `proxy-authority-v1`; belongs in every future grouping identity |
| `parse_status` | `missing`, `sanitized`, `invalid`, `valid_dns`, `valid_ipv4`, `valid_ipv6`; Go additionally fails closed as `unsupported_idna_version` |
| `authority_source` | `http_authority`, `connect_authority`, `quic_authority`, `sni`, `original_destination`, `legacy_host`, or `query`; unknown source is invalid |
| `sanitization_status` | Explicit producer flag or recognized `hmac:` marker gives `sanitized`; otherwise `not_sanitized` describes this normalization input only |

Effective routing port is a separate observation and is never supplied by this
contract. A legacy host with no sanitization flag does not establish the original
privacy policy. Preserve that provenance separately when stage 3 adds evidence.
Sanitized inputs never acquire normalized host/domain/port grouping keys.
Invalid values may retain private raw evidence but never valid grouping keys.
Raw evidence is not embedding prose, logging content or exported diagnostics.
Existing hostname privacy policy must run before any future raw-field persistence.

The parser rejects credentials, paths, query/fragment components, escapes, zone
identifiers, whitespace, controls, invalid labels and invalid ports. Numeric
dotted forms must be strict IPv4; leading zeros are rejected. Bare IPv6 is accepted
only as a complete literal: `2001:db8::1:443` has no port. An explicit IPv6 port
requires brackets. A malformed unbracketed IPv6-plus-port cannot be salvaged by
splitting its last colon. Parsing never performs DNS resolution.

## IDNA and PSL decision

Use UTS #46 nontransitional processing, STD3 ASCII rules, label/hyphen/length,
Bidi and ContextJ validation, Unicode 15.0.0. Scala adds ICU4J 73.2 because
`java.net.IDN` uses IDNA2003 and maps sharp-s differently. Go reuses the existing
`golang.org/x/net/idna` v0.55.0 dependency with an explicit profile. Go 1.26 is the
supported contract toolchain: x/net selects Unicode 17 tables starting with Go
1.27, so v1 deliberately refuses that table change. Toolchain upgrades require
an explicit normalization migration, not a silent grouping change.
See [ICU IDNA options](https://unicode-org.github.io/icu-docs/apidoc/released/icu4j/com/ibm/icu/text/IDNA.html)
and [Go IDNA options](https://pkg.go.dev/golang.org/x/net/idna).

Pin the complete Mozilla PSL (ICANN **and PRIVATE**) at commit
`52b71b3c4576ff77450cc7ebcfc7f34a916af3f9`, SHA-256
`3d92f70d719426d7e82dc4aee181058d0ad570d2559f0ea3ece8e731a25e5f33`.
The data retains its MPL notice and upstream Unicode rules. Both implementations
canonicalize rules using the selected IDNA profile and implement the PSL's
longest-match, wildcard, exception and implicit-star algorithm. `a.github.io`
and `alice.blogspot.com` are registrable domains under the private policy.
This is not final-two-label splitting. See the
[upstream PSL algorithm](https://github.com/publicsuffix/list/wiki/Format).

Go's existing `publicsuffix.EffectiveTLDPlusOne` is suitable for many uses but
does not expose arbitrary pinned PSL data. Java IDN, JDK URI and existing HTTP
URL parsers do not jointly provide this exact IDNA/PSL contract. The shared
small matcher avoids adding another PSL library with an independent data revision.
Both runtime artifacts bundle the same list; neither reads a parent checkout.
Both test suites load bundled byte-identical copies of the shared 61-case corpus;
the parent Python contract test detects fixture or PSL drift.

## Migration policy

Unversioned stored values remain `unknown_legacy`; do not label them v1 because
their spelling happens to agree. Raw observations, retained envelopes, existing
source IDs, normalized-text SHA-256 and existing document identities stay intact.
New grouping keys include version, source kind and endpoint scope. Host grouping
does not imply authority/port grouping. SNI does not overwrite original destination.

Any change to Unicode tables, parsing, private policy or PSL bytes requires a new
normalization version and a coexisting corpus. Recompute affected projections
through Octopus with monotonic evidence revisions and select outdated documents
through existing preparation. Re-embed only when effective document text or
embedding preprocessing changes. Never overwrite raw evidence, reactivate an old
document, or mix versions in a group. Activation remains gated on later schema,
scope and preparation-fencing work.
