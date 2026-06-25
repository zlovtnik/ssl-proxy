# Operator Runbook

## Operational Procedures

---

### 1. Adding a New Obfuscation Profile

#### Steps

1. **Edit `src/obfuscation.rs`:**
   - Add new domain patterns to the `FOX_DOMAINS` array
   - Add new variant to the `Profile` enum
   - Update `as_str()` conversion method
   - Extend match statement in `classify_obfuscation()`

2. **Update configuration struct:**
   - Add profile enable flag in `src/config.rs`
   - Add environment variable mapping

3. **Verify implementation:**
   ```bash
   cargo test obfuscation::tests
   ```

4. **Publish and redeploy the image:**
   ```bash
   make registry-build-ssl-proxy REGISTRY=<server-local-ip>:5000
   export REGISTRY=<server-local-ip>:5000
   docker compose pull ssl-proxy wg-udp-frontdoor
   docker compose up -d ssl-proxy wg-udp-frontdoor
   ```

---

### 2. Updating Blocklist URL

Set the environment variable in your compose override or shell:

```bash
BLOCKLIST_URL=https://example.com/blocklist.txt
```

Blocklist is automatically refreshed on service startup and every 24 hours.

Apply changes by restarting the service:

```bash
docker compose restart ssl-proxy
```

---

### 3. Rotate WireGuard and Runtime Secrets

Use the rotator in `apps/wg-key-rotator` for stable-port scheduled rotation. It creates a candidate key generation under ignored local state, starts `ssl-proxy-next`, and updates `wg-udp-frontdoor` so old and new WireGuard keysets can both receive packets on the stable public UDP ports.

1. **Stage a candidate generation from the repository root:**
   ```bash
   cd apps/wg-key-rotator
   bin/wg_key_rotator stage
   bin/wg_key_rotator start-next
   ```

2. **Distribute generated client bundles:**
   - Bundles are written under `secrets/wg-rotation/generations/<generation>/client-bundles/`
   - Private keys, PSKs, admin keys, and obfuscation keys stay in ignored local files
   - Clients keep the same public UDP endpoint; the frontdoor fans packets to active and candidate backends

3. **Promote after every configured peer handshakes with the candidate:**
   ```bash
   bin/wg_key_rotator status
   bin/wg_key_rotator promote
   ```

4. **Rollback if migration does not complete:**
   ```bash
   bin/wg_key_rotator rollback
   ```

> **Important:** Do not hand-edit tracked example configs with live keys. Live WireGuard keys, peer configs, admin API keys, and obfuscation keys are generated under ignored local paths.

---

### 3.1 Compose Runtime Compatibility Mode for Peer Config Mounts

- `ssl-proxy` is intentionally pinned to `user: "0:0"` in `docker-compose.yaml` for compatibility with host bind-mounted peer config files such as `config/<peer>/<peer>.conf` that are commonly `0600`.
- This preserves legacy startup behavior where entrypoint key sync reads/writes `PublicKey` and `PresharedKey` data from configured `/config/<peer>/*.conf` files.
- Security tradeoff: root-in-container plus `NET_ADMIN` increases impact if the container is compromised. Keep `--privileged` disabled and avoid broad writable host mounts.

---

### 4. Verify Container Provenance for WireGuard Startup

First-party service images are built off-host and pulled from the local
registry. See [local-registry-workflow.md](local-registry-workflow.md) for the
registry setup, access control, and buildx workflow.

1. **Publish a fresh image with explicit metadata:**
   ```bash
   export VCS_REF="$(git rev-parse --short HEAD)"
   export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   make registry-build-ssl-proxy REGISTRY=<server-local-ip>:5000 TAG="$VCS_REF"
   ```

2. **Pull and recreate the runtime container on the server:**
   ```bash
   export REGISTRY=<server-local-ip>:5000
   export IMAGE_TAG="$VCS_REF"
   docker compose down --remove-orphans
   docker compose pull ssl-proxy wg-udp-frontdoor
   docker compose up -d
   ```

3. **Compare the pulled image and compose input:**
   ```bash
   docker images "$REGISTRY/ssl-proxy"
   docker compose config | sed -n '20,55p'
   ```

4. **Verify the runtime fingerprint and rendered config:**
   ```bash
   docker compose logs ssl-proxy | grep '\[startup-fingerprint\]'
   docker compose exec -T ssl-proxy sed -n '1,12p' /run/wireguard/wg0.conf
   ```

   If a mounted template drifted and duplicated `Address = ...` lines, startup now canonicalizes them back to one line before bringing the BoringTun-backed `wg0` interface up.

5. **If logs contradict the repo:**
   - Remove the old container with `docker compose down --remove-orphans`
   - Re-push the image, then run `docker compose pull && docker compose up -d`
   - Re-check the `[startup-fingerprint]` lines before debugging WireGuard behavior

---

### 5. Oracle ADB Connection & Views

1. **Place auto-login Oracle wallet files in `./wallet/` directory**
   - Restart the container after adding the wallet so the startup preflight can enable Oracle persistence.
   - `GET /ready` on `http://127.0.0.1:3002/ready` stays `503` until the wallet contains the configured `ORACLE_CONN` alias, default `mainerc_high`, plus `tnsnames.ora`, `sqlnet.ora`, `cwallet.sso`, and a non-empty password file.

2. **Connect using SQL*Plus:**
   ```bash
   sqlplus USCIS_APP@mainerc_high
   ```

3. **Available Audit Views:**
   ```sql
   -- Session traffic summary
   SELECT * FROM v_proxy_session_stats;

   -- Obfuscation events
   SELECT * FROM v_obfuscation_log;

   -- Blocked requests
   SELECT * FROM v_blocked_requests;

   -- Daily bandwidth usage
   SELECT * FROM v_daily_bandwidth;
   ```

All views are optimized for ADB columnar storage.

---

### 6. Prometheus / Vector Pipeline Setup

> Note: the non-vector Grafana/Loki/Jaeger/Prometheus rollout in `docs/observability-workmap-non-vector.md` explicitly excludes this Vector-profile pipeline.

1. **Start pipeline:**
   ```bash
   LOG_FORMAT=json ./ssl-proxy | vector --config vector.toml
   ```

2. **Configuration:**
   - `vector.toml` filters audit events
   - Normalizes timestamps for ClickHouse
   - Batches inserts for optimal warehouse performance

3. **Environment Variables:**
   ```text
   CLICKHOUSE_URL=http://clickhouse:8123
   CLICKHOUSE_USER=default
   CLICKHOUSE_PASSWORD=yourpassword
   ```

4. **Operational health and dashboard are available at:**
   ```text
   http://127.0.0.1:3002/health
   http://127.0.0.1:3002/dashboard
   ```

---

### 7. Compose Startup Log Notes

- `java-coordinator` is the sync control-plane service. The source still lives under `services/zig-coordinator/` for historical reasons, but the runtime service is Java/Spring/Camel; inspect it with `docker compose logs java-coordinator`.
- `sql/postgres.sql` is a compatibility shim that `\ir`-includes the split schema tree (`sql/extensions`, `sql/tables`, `sql/functions`, etc.). Maintain split schema files directly and keep `sql/postgres.source.sql` in sync as the aggregate reference when split objects change.
- `services/schema-migrator` is the canonical CLI for schema ordering and validation:
  - `cd services/schema-migrator && sbt "run --sql-dir ../../sql list"`
  - `cd services/schema-migrator && sbt "run --sql-dir ../../sql validate"`
  - `export DATABASE_URL=... && cd services/schema-migrator && sbt "run --sql-dir ../../sql apply"`
- `schema-migrator apply` bootstraps `schema_control.schema_objects`, `schema_control.schema_apply_log`, and the single-row readiness view `schema_control.schema_ready`. Runtime apps should gate startup with:
  ```sql
  select ready, all_applied, pending_count, failed_count, failed_objects
  from schema_control.schema_ready;
  ```
  Proceed only when `ready = true` and `failed_count = 0`. `atheros-search` enforces this by default before serving traffic or starting its embedded worker path; tune with `ATHSEARCH_SCHEMA_READY_TIMEOUT_MS`, `ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS`, or temporarily bypass legacy environments with `ATHSEARCH_SCHEMA_READY_REQUIRED=false`. Any standalone `vec-worker` deployment should perform the same query before leasing embedding jobs.
- Postgres init scripts are intentionally unused. A line such as `/usr/local/bin/docker-entrypoint.sh: ignoring /docker-entrypoint-initdb.d/*` is expected when that directory has no mounted scripts; inspect it with `docker compose logs postgres`.
- Redpanda is part of the compose stack and runs Redpanda for sync topics. The Redpanda banner, storage directory, monitor address, and `Server is ready` indicate normal readiness; inspect with `docker compose logs redpanda`.
- If any expected message is missing, run `docker compose ps` and `docker compose logs <service>` for the affected service, then check failed healthchecks, missing volumes, and environment values before restarting that service.
- `redpanda-init` must complete successfully before `java-coordinator` is healthy. It creates the Redpanda topics in `docker/redpanda/topics.manifest`, including `wireless.audit`, `sync.scan.request`, `sync.oracle.load`, and `sync.oracle.result`. Consumer groups are created by the coordinator at runtime: `zig-coordinator-scan`, the legacy-compatible `oracle-worker-load` load group, and `zig-coordinator-result`.
- `atheros-sensor` auto-detects a wireless capture interface when `ATH_SENSOR_DEVICE` is empty (prefers `ath9k_htc`, then falls back to the lexicographically first wireless interface under `/sys/class/net`). Set `ATH_SENSOR_DEVICE=wlxc01c3038d5e8` or another exact wireless interface to pin capture to a specific adapter.

### 8. Wireless Audit Minute Cleanup

Use the cleanup function after confirming an audit time range is safe to normalize. It truncates `wireless.audit` `observed_at` values to the UTC minute and removes duplicate rows with the same wireless fingerprint, keeping the newest row by `updated_at`, then `created_at`, then `dedupe_key`.

```sql
SELECT * FROM normalize_wireless_audit_minutes(
  '2026-04-29 00:00:00+00'::timestamptz,
  '2026-04-30 00:00:00+00'::timestamptz
);
```

Quick sync-plane inspection:

```sh
scripts/sync-status.sh
```

Manual checks:

```sh
docker compose run --rm redpanda-init rpk topic describe sync.scan.request --brokers redpanda:9092
docker compose run --rm redpanda-init rpk topic describe sync.oracle.load --brokers redpanda:9092
docker compose run --rm redpanda-init rpk group describe zig-coordinator-scan --brokers redpanda:9092
curl -s http://127.0.0.1:8081/actuator/prometheus | grep '^coordinator_redpanda_consumer_lag_records'
docker compose exec -T postgres psql -U sync -d sync -c "select status, count(*) from sync_events group by status"
docker compose exec -T postgres psql -U sync -d sync -c "select count(*) from sync_jobs; select count(*) from sync_batches;"
```

KEDA-ready coordinator lag PromQL uses `max(...)` so multi-replica scrapes do not double count the same consumer-group lag:

```promql
max(coordinator_redpanda_consumer_lag_records{job="java-coordinator",role="scan",topic="sync.scan.request"})
max(coordinator_redpanda_consumer_lag_records{job="java-coordinator",role="result",topic="sync.oracle.result"})
```

If `java-coordinator` logs `event=oracle_load status=failed` or `unsupported stream_name`, confirm the coordinator load consumer is subscribed to the load topic and that `SYNC_ORACLE_STREAM_NAMES` contains only streams with Oracle sink support:

With `ORACLE_SINK_ENABLED=true`, `java-coordinator` validates the mounted wallet before the Kafka load consumer can process batches. Wallet preflight failures use these exact messages in `java-coordinator` logs: `wallet directory missing`, `missing Oracle wallet artifact`, `Oracle TNS alias not found`, `missing Oracle password file`, and `Oracle password file is empty`. Missing wallet artifact errors include a sanitized listing of `/app/wallet`. Unrecoverable corrupt dispatch rows are marked with `sync.oracle.load payload_ref missing and stored payload unavailable`.

`ORA-06550` with `PLS-00201: identifier 'WIRELESS_UPSERT_SENSOR' must be declared` means the connected `ORACLE_USER` can reach Oracle but cannot see the active sink schema from `sql/oracle.sql`; apply the Oracle DDL to that schema or grant visible synonyms for the required tables and procedures.

```sh
docker compose config java-coordinator | sed -n '/target: \/app\/wallet/,+4p'
docker compose exec -T java-coordinator sh -lc 'ls -la /app/wallet && test -r /app/wallet/tnsnames.ora && test -r /app/wallet/sqlnet.ora && test -r /app/wallet/cwallet.sso && test -s "${ORACLE_PASS_FILE:-/run/secrets/oracle_password.txt}"'
docker compose run --rm redpanda-init rpk group describe oracle-worker-load --brokers redpanda:9092
docker compose exec -T java-coordinator env | grep '^SYNC_ORACLE_STREAM_NAMES='
docker compose exec -T postgres psql -U sync -d sync -c "select job.stream_name, batch.status, count(*) from sync_batches batch join sync_jobs job on job.job_id = batch.job_id group by job.stream_name, batch.status order by job.stream_name, batch.status"
```

Recovery path:

```sh
docker compose run --rm redpanda-init
docker compose restart java-coordinator
```

If the consumer group offset is stuck after a poison load message, reset it after the bad row is addressed:

```sh
docker compose run --rm redpanda-init rpk group offset-delete oracle-worker-load --topics sync.oracle.load --brokers redpanda:9092
docker compose restart java-coordinator
```

For attribution, usernames come from the device registry. Passive wireless-only observations should remain `identity_source='unknown'` until a registered device record provides a reliable correlation such as `wg_pubkey`, claim token, hostname, or MAC hint.

### Device upsert response note

`DeviceUpsertResponse.claim_token` is now optional on device upsert responses.

- `claim_token` is returned (`Some`) only when a new device is created or when `regenerate_claim_token=true` is set on the request.
- For metadata-only updates to an existing device, `claim_token` is `None` and omitted from JSON (`skip_serializing_if = "Option::is_none"`).

Client migration guidance: treat `claim_token` as nullable/optional and only persist a new token when the field is present; do not assume every upsert response contains a token string.

---

### 9. Security Hardening Controls (Threat-Model Gap Closure)

Set these environment variables for hardened control-plane behavior:

```text
ADMIN_BIND_ADDR=127.0.0.1
ADMIN_REQUIRE_MFA_CLAIM=true
ADMIN_MFA_HEADER_NAMES=x-auth-amr,x-auth-acr,x-mfa-claim
ENABLE_NETWORK_SEGMENTATION=true
ALLOWED_BINARY_SHA256=<sha256 of ssl-proxy binary>
ALLOWED_CONFIG_SHA256=server.conf=<sha256>,peer.conf=<sha256>
INTEGRITY_CONFIG_PATHS=config/templates/server.conf,config/templates/peer.conf
PATCH_CADENCE_REPORT_PATH=/var/run/security/patch-cadence.json
RECOVERY_DRILL_REPORT_PATH=/var/run/security/recovery-drills.json
```

`ALLOWED_CONFIG_SHA256` is matched by config filename, not by a shared allowlist across all config paths.
`v_payload_audit_sensitive` is intended to remain owner-only; if operators grant access, they should do so through DBA-managed least-privilege roles and database audit policy outside this repo.

When configured, additional admin endpoints are exposed (still under API key + MFA middleware):

```text
GET /security/patch-cadence
GET /security/recovery-drills
```

---

### 10. Non-Vector Observability Rollout Ops

This runbook section covers the non-vector observability control plane. Full rollout details live in `docs/observability-workmap-non-vector.md`.

Ports:

```text
Grafana:     127.0.0.1:3004
Prometheus:  127.0.0.1:9090
Loki:        127.0.0.1:3100
Jaeger UI:   127.0.0.1:16686
OTel gRPC:   127.0.0.1:4317
OTel HTTP:   127.0.0.1:4320
```

Verification:

```sh
docker compose up -d prometheus loki promtail jaeger otel-collector grafana postgres-exporter redis-exporter pushgateway
docker compose ps
curl -s http://127.0.0.1:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health, instance: .labels.instance}'
curl -s "http://127.0.0.1:16686/api/services" | jq
curl -s http://127.0.0.1:3003/metrics | head -n 30
curl -s http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=observability_job_last_run_unixtime' | jq
```

Scope guardrail: this rollout excludes vector-profile services (`vec-worker*`, `ollama`) and does not change `vector.toml`.
