# Advisory plans

This directory holds review and implementation workmaps that are independent of
the in-progress Atheros reporting plans in [`plans/`](../plans/README.md).

| Priority | Plan | Dependency | Status | Scope |
| --- | --- | --- | --- | --- |
| P0/P1 first | [001: Search performance and quality workmap](001-atheros-search-performance-quality-workmap.md) | Reconcile the dirty Integration Console worktree; establish a fixed baseline | READY FOR EXECUTION | Audit of the 21 numbered recommendations, backend quality rules, verification, and rollout |
| P0/P1 staged | [002: Proxy-only RAG and ML workmap](002-proxy-rag-ml-workmap.md) | Fresh coverage measurements; versioned evidence contracts; explicit proxy scopes | PLANNED | Eight-stage tasklist for normalization, evidence, reconciliation, bounded recovery, behavior, retrieval, evaluation and GitOps release |
| Memory audit | [003: Octopus memory audit](003-octopus-memory-audit.md) | Live measurements before JVM promotion; select implementation scope | AUDITED | Active ingestion retention, partition buffering, JSON allocation, JVM sizing and deferred projection/retention improvements |
| P0/P1 selected | [004: Proxy ISP privacy workmap](004-proxy-isp-privacy-workmap.md) | Execute 005, then manual adapters, then integrated selection | ADVISOR PLAN COMPLETE | Four selected priorities only; implementation not started |
| P0 | [005: Leak containment and encrypted DNS](005-vpn-leak-containment-dns.md) | Actual client OS/admin access; owned relay and effective DNS evidence | TODO | Persistent client containment, explicit outer routes and dual-stack/DNS failure matrix |
| P1 | [006: MASQUE CONNECT-UDP over HTTP/3](006-masque-connect-udp.md) | 005 containment contract; pinned API/dependency gate; UDP 443 ownership | TODO | Manual datagram adapter, independent interop, MTU and real WG validation |
| P1 | [007: Genuine HTTPS fallback](007-https-transport-fallback.md) | 005 containment contract; shared packet boundary; tested HTTPS front | TODO | Normal website behavior, authenticated reliable carriage and loss/UDP-block tests |
| P1 | [008: Authenticated transport selection](008-authenticated-transport-selection.md) | 005 plus proven manual 006/007 adapters for integrated release | TODO | Fresh candidate-bound health, bounded recovery, hysteresis and contained outage |

## Selected privacy execution notes

- 005 precedes transport promotion. Its live client OS and effective DNS checks
  remain required even if repository tests pass.
- 006 and 007 may be designed independently after the containment contract;
  serialize their shared shim/config/transport-interface edits.
- 008 pure state tests may run alongside adapter development. Automatic
  selection is integrated only after the manual adapters and leak matrix pass.
- New dependency authorization, endpoint ownership, TLS provisioning and the
  current WAN TCP 443 publication restriction are explicit gates. Plan completion
  does not authorize public endpoint publication.
- ECH, shaping, multi-hop, alternate VPN ecosystems, Tor integration and general
  performance/crypto optimization remain deferred. They are not selected tasks.
- Existing template routes, DoT examples, chaff, successful UDP sends and H3 TCP
  CONNECT were considered insufficient evidence of verified containment,
  authenticated liveness or an implemented MASQUE transport.

Status values for executor plans: TODO, IN PROGRESS, DONE, or BLOCKED with the
specific missing prerequisite. Record local implementation and production/live
validation separately; a missing environment test is not a passing result.

Privacy-plan verification on 2026-10-23: `python3 scripts/check-docs.py` and
`git diff --check` passed. All six edited planning files also passed an explicit
trailing-whitespace check, including untracked files; new workmaps use ASCII.
Independent read-only reviews checked transport contracts and containment/
liveness gates. No runtime tests or client/relay/production changes were made
by this documentation update.

The workmap is a plan, not a claim that its proposed changes have been made.
Executors must recheck the recorded source state and preserve unrelated edits.
