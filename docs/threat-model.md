# SSL Proxy Threat Model (Initial Draft)

## 1. System summary

This system is a WireGuard-first privacy proxy where clients enter through a UDP tunnel on port `443` and route full-tunnel traffic (`0.0.0.0/0`, `::/0`) through the containerized stack. Traffic from the `wg0` interface is policy-enforced through transparent interception: TCP `80/443` is redirected with `iptables REDIRECT` to the transparent proxy listener on port `3001`.

The transparent path performs host-based policy decisions (including SNI-dependent handling), applies optional obfuscation rules, and emits operational/audit events. Optional explicit HTTP/HTTPS proxy mode exists for controlled debugging, but is disabled by default.

Operational and compliance-relevant data is exposed through host-local admin/API endpoints on port `3002` (`/health`, `/ready`, dashboard/WebSocket surfaces). Readiness specifically reflects Oracle wallet + DB connectivity posture.

Oracle persistence is feature-gated (`oracle-db`) and used as the durable audit/event ledger path when enabled.

### Trust boundaries (initial)

- **Client device boundary:** Untrusted endpoint and user-controlled applications.
- **WireGuard ingress boundary:** Encrypted tunnel ingress at host UDP `443`.
- **Container runtime boundary:** In-container routing, transparent proxying, and policy logic.
- **Admin/control-plane boundary:** Internal admin API/dashboard on `127.0.0.1:3002`.
- **External dependency boundary:** Oracle DB/audit persistence and upstream DNS/origin networks.

### Known/declared unknowns for compliance follow-up

- **Unknown:** Privileged admin user count and role segmentation for admin endpoints.
- **Unknown:** Third-party operator model (managed service provider, co-admins, or contractor access).
- **Unknown:** Key lifecycle and rotation SLAs for WireGuard server keys and API keys.
- **Unknown:** Exact retention schedule and immutability/legal-hold guarantees for persisted audit data.
- **Unknown:** Formal data-classification matrix for captured metadata/payload-adjacent fields.

## 2) attacker motivation assessment

Primary attacker motivations likely include:

- **Policy evasion:** Bypassing domain controls, transparent filtering, or protocol constraints.
- **Data exfiltration:** Extracting sensitive corporate/user data via allowed channels.
- **Identity and session abuse:** Hijacking authenticated paths, replaying credentials/API keys, or forging attribution.
- **Operational disruption:** Denial of service against WireGuard ingress, proxy hot path, or Oracle-backed audit writes.
- **Forensic degradation:** Disabling, delaying, or corrupting audit trail persistence to reduce accountability.

Motivation intensity is **high** where this proxy is used as a compliance control point and legal/audit evidence source.

## 3) attacker profile assessment

Likely attacker profiles:

- **External opportunistic actor:** Internet-based scanning/exploitation of exposed surfaces (primarily WireGuard ingress and any misexposed admin ports).
- **External targeted actor:** Goal-oriented adversary attempting to evade monitoring or extract high-value traffic metadata.
- **Authenticated but malicious user:** Valid tunnel user abusing authorized connectivity for prohibited destinations or high-volume scraping/exfiltration.
- **Compromised endpoint malware:** Uses legitimate tunnel user flows to blend malicious traffic with normal activity.
- **Infrastructure-adjacent adversary:** Actor with partial control over DNS paths, host networking, CI/CD artifacts, or secrets supply chain.
- **Privileged insider/operator:** Admin-capable user able to alter policy, logging, or persistence behavior.

## 4) insider scenarios

1. **Admin endpoint misuse:** Privileged operator changes runtime behavior (filters, feature flags, auth config) to weaken enforcement or conceal activity.
2. **Audit suppression by configuration drift:** Insider disables `oracle-db` path, breaks wallet/TNS configuration, or normalizes repeated `/ready` failures without escalation.
3. **Credential/key abuse:** Insider reuses/leaks `ADMIN_API_KEY`, WireGuard private keys, or DB credentials to impersonate trusted control-plane operations.
4. **Selective policy tampering:** Insider modifies blocklists/allowlists to create covert egress channels while preserving apparent normal operation.
5. **Evidence manipulation pre-persistence:** Insider exploits queueing/flush semantics to intentionally drop high-risk events before durable write.

## 5) external scenarios

1. **WireGuard ingress abuse/flooding:** Attackers degrade service by saturating UDP `443` or abusing handshake behavior to exhaust resources.
2. **Transparent-path evasion:** Attackers attempt TLS/SNI edge-case evasion (non-SNI flows, protocol tunneling, fragmented signatures) to bypass host-based controls.
3. **Admin surface exposure mistake:** Misconfiguration exposes admin/dashboard endpoints beyond localhost, enabling enumeration or unauthorized API calls.
4. **Dependency compromise:** Upstream DNS/origin manipulation or blocklist-feed poisoning influences routing and policy outcomes.
5. **Oracle path disruption:** Network/database interference causes persistent audit write failures, reducing detection and compliance evidence quality.
6. **Credential brute force/replay:** Attempts against explicit proxy credentials (if enabled) or stolen tokens/keys from adjacent systems.

## 6) prioritized scenario list

Priority is based on impact to enforcement integrity + audit integrity.

1. **P1 — Audit trail loss or tampering** (insider or external via persistence disruption).
2. **P1 — Unauthorized admin/control-plane access** (misexposure, weak auth, key leakage).
3. **P1 — Transparent policy evasion leading to undetected prohibited traffic**.
4. **P2 — Authenticated user data exfiltration over allowed channels**.
5. **P2 — Blocklist/source poisoning causing false allow/deny outcomes**.
6. **P2 — WireGuard ingress resource exhaustion/availability attack**.
7. **P3 — Legacy explicit-proxy path misuse in debug-enabled deployments**.

## 7) attack lifecycle defensive map

| Lifecycle phase | Representative threat | Current/expected defensive control | Coverage status |
|---|---|---|---|
| Reconnaissance | Discovery of exposed ports/endpoints | Host-local admin binding expectation (`127.0.0.1:3002`), minimal externally exposed services | **Partial** (requires deployment verification) |
| Initial access | Stolen credentials/API keys, misconfigured admin exposure | `ADMIN_API_KEY` support, operational hardening practices | **Partial / Unknown** (rotation + MFA model not documented) |
| Execution | Policy-bypass traffic over tunnel | Transparent interception of TCP `80/443`, SNI-dependent controls, optional fail-closed behavior | **Partial** (non-SNI and protocol edge cases need explicit validation) |
| Persistence | Long-lived covert channels by authenticated users | Session/event tracking and blocklist enforcement paths | **Partial** (user identity correlation maturity in-progress) |
| Privilege escalation | Abuse of operator/admin capabilities | Role separation expectations, feature gating | **Unknown** (actual RBAC/role count not documented) |
| Defense evasion | Suppressing events or disabling DB persistence | `/ready` Oracle readiness signal, audit/event pipeline design | **Partial** (tamper-evidence controls not yet explicit) |
| Collection/Exfiltration | High-volume transfer via allowed domains/APIs | Blocklist + heuristics + future transaction/scraping detection work | **Partial** |
| Impact | Compliance failure, forensic blind spots, outage | Health/readiness endpoints, planned observability/alertging improvements | **Partial** |

## 8) open questions/assumptions

### Open questions

- What is the authoritative count of privileged users/operators with admin endpoint access?
- Is there a third-party operator or managed-service model with direct production access?
- What are required key rotation periods for WireGuard keys, API keys, and Oracle credentials?
- What retention/immutability controls are mandatory for audit records (e.g., WORM/legal hold duration)?
- Which admin endpoints are currently authn/authz protected versus network-location protected only?
- What is the approved incident response SLA for sustained `/ready` Oracle failures?

### Working assumptions (to validate)

- Admin/control-plane services are intended to remain host-local and not internet-exposed.
- WireGuard is the primary ingress path; explicit proxy remains exceptional/debug-only.
- Oracle-backed persistence is required for compliance-grade evidence in regulated deployments.
- Fail-closed behavior for ambiguous TLS metadata (e.g., no SNI) is expected in strict environments.
- Compliance reviewers will resolve unknown ownership and role-model questions before production sign-off.

## 9) supplemental gap-driven defensive view

### Top scenarios

1. Stolen credentials are used to access proxy services and blend into normal traffic.
2. Unpatched edge/runtime components are exploited for remote code execution.
3. Lateral movement from a compromised workload reaches proxy control/data-plane services.
4. Unauthorized binaries/config changes alter proxy behavior or disable controls.
5. Data exfiltration occurs through high-volume or covert outbound flows.
6. Ransomware/destructive actions disrupt logging and operational continuity.

### Attack lifecycle defensive map

| Scenario | Best intervention stage | Recommended defense | Owner | Verification signal |
|---|---|---|---|---|
| Stolen credentials used to access proxy/admin paths | Initial access | **MFA enforcement for admin + identity-proxy auth** (Epic 1). **Gap: YES** — no explicit MFA requirement exists in current workmap. | Security Engineering + Platform | 100% admin/API auth events include MFA claim; alert on any non-MFA success. |
| Exploit of unpatched runtime/proxy dependencies | Weaponization / delivery | **Patch cadence SLA + vulnerability triage workflow** (Epic 5 governance). **Gap: YES** — no patch cadence control exists in current workmap. | SRE + Security Engineering | Median patch latency under SLA (e.g., 14 days high, 48h critical); weekly vuln report with zero overdue criticals. |
| Lateral movement into proxy data/control plane | Privilege escalation / lateral movement | **Network segmentation + least-privilege service boundaries** (Epic 4 capacity/fairness + platform hardening). **Gap: YES** — segmentation control is not currently represented. | Platform Engineering | Denied east-west attempts logged; segmentation policy conformance checks pass in CI/CD and runtime audit. |
| Tampering with binaries/configuration to bypass controls | Installation / defense evasion | **Allowlisting and integrity checks for binaries/config + signed artifact validation** (Epic 2 control-plane hardening). **Gap: YES** — integrity/allowlisting control not currently represented. | Platform Engineering + Security Engineering | Boot/startup integrity attestation success; unauthorized hash/config drift events trigger high-severity alert. |
| Data exfiltration via bulk download or scraping patterns | Actions on objectives | **DLP/egress anomaly detection** (Epic 3.3 already planned). **Gap: NO** — covered by scraping + high-volume egress detection tasks. | Security Operations + Backend | Egress anomaly events generated for threshold breaches; tuned precision/recall reviewed weekly. |
| Ransomware/destructive event impacting recovery of service/audit | Impact | **Tested recovery runbooks (tabletop + restore drills)** (Epic 5 operations readiness). **Gap: YES** — tested recovery runbooks are not currently explicit. | SRE + Compliance | Quarterly restore drill pass rate 100%; documented RTO/RPO met in exercise evidence. |

### Gap-Driven Backlog Additions (to corresponding epics)

#### Epic 1 — Transaction-Level Audit & User Session Tracking

- [x] **1.1.5 MFA claim enforcement for privileged/admin access (NEW):** Require MFA claim from upstream identity provider for admin routes and high-risk actions; emit audit event when claim is missing and deny by policy.

#### Epic 4 — Bandwidth & Performance Hardening

- [x] **4.5.1 Network segmentation policy for control/data plane (NEW):** Define and enforce network policy boundaries between WireGuard ingress, proxy runtime, DB writer, and admin endpoints; default deny east-west except explicit allow rules.

#### Epic 2 — Intelligent Blocklist Infrastructure

- [x] **2.4.1 Binary/config allowlisting and integrity attestation (NEW):** Enforce signed release artifact verification at startup and periodic config hash validation; quarantine/alert on drift from approved allowlist.

#### Epic 5 — Observability & Alerting

- [x] **5.4.1 Security patch cadence SLA and reporting (NEW):** Track dependency and base-image patch age with severity-based SLA and overdue alerting.
- [x] **5.4.2 Recovery runbook validation program (NEW):** Add scheduled backup-restore and failover drills for audit stores and critical proxy components with evidence retention for compliance.
