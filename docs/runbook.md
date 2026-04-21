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

4. **Rebuild container:**
   ```bash
   docker compose build ssl-proxy
   docker compose up -d
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

### 3. Rotate WireGuard Key Pair

1. **Generate new server keys:**
   ```bash
   wg genkey | tee config/server/privatekey-server | wg pubkey > config/server/publickey-server
   ```

2. **Update server configuration:**
   - Keep the private key in `config/server/privatekey-server`
   - The container will render `/run/wireguard/wg0.conf` from `config/templates/server.conf`
   - Distribute the updated public key to all peers

3. **Restart service:**
   ```bash
   docker compose restart ssl-proxy
   ```

> **Important:** All connected clients will require updated configuration with the new server public key.

---

### 4. Verify Container Provenance for WireGuard Startup

1. **Force a fresh build with explicit metadata:**
   ```bash
   export VCS_REF="$(git rev-parse --short HEAD)"
   export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   docker compose down --remove-orphans
   docker compose up -d --build
   ```

2. **Compare the built image and compose input:**
   ```bash
   docker images boringtun-ssl-proxy
   docker compose config | sed -n '20,55p'
   ```

3. **Verify the runtime fingerprint and rendered config:**
   ```bash
   docker compose logs ssl-proxy | grep '\[startup-fingerprint\]'
   docker compose exec -T ssl-proxy sed -n '1,12p' /run/wireguard/wg0.conf
   ```

   If a mounted template drifted and duplicated `Address = ...` lines, startup now canonicalizes them back to one line before bringing the BoringTun-backed `wg0` interface up.

4. **If logs contradict the repo:**
   - Remove the old container with `docker compose down --remove-orphans`
   - Rebuild with `docker compose up -d --build`
   - Re-check the `[startup-fingerprint]` lines before debugging WireGuard behavior

---

### 5. Oracle ADB Connection & Views

1. **Place Oracle wallet files in `./wallet/` directory**
   - Restart the container after adding the wallet so the startup preflight can enable Oracle persistence.
   - `GET /ready` on `http://127.0.0.1:3002/ready` stays `503` until the wallet contains the `mainerc_tp` alias and the required wallet artifacts.

2. **Connect using SQL*Plus:**
   ```bash
   sqlplus USCIS_APP@mainerc_tp
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

- `zig-coordinator` is the sync control-plane service. On startup it applies the Postgres sync schema with `psql -f /app/schema/postgres.sql`; confirm this line appears with `docker compose logs zig-coordinator`.
- Postgres init scripts are intentionally unused. A line such as `/usr/local/bin/docker-entrypoint.sh: ignoring /docker-entrypoint-initdb.d/*` is expected when that directory has no mounted scripts; inspect it with `docker compose logs postgres`.
- NATS is part of the compose stack and runs JetStream for sync subjects. The JetStream banner, storage directory, monitor address, and `Server is ready` indicate normal readiness; inspect with `docker compose logs nats`.
- If any expected message is missing, run `docker compose ps` and `docker compose logs <service>` for the affected service, then check failed healthchecks, missing volumes, and environment values before restarting that service.
- `nats-bootstrap` must complete successfully before `zig-coordinator` is healthy. It creates `AUDIT_STREAM` for `wireless.audit`, `sync.scan.request`, `sync.oracle.load`, and `sync.oracle.result`, plus the `zig-coordinator-scan` durable consumer.
- `atheros-sensor` auto-detects a wireless capture interface when `ATH_SENSOR_DEVICE` is empty (prefers `ath9k_htc`, then falls back to the first wireless interface under `/sys/class/net`). Set `ATH_SENSOR_DEVICE=wlxc01c3038d5e8` or another exact wireless interface to pin capture to a specific adapter.

Quick sync-plane inspection:

```sh
scripts/sync-status.sh
```

Manual checks:

```sh
docker compose run --rm nats-bootstrap nats --server nats://nats:4222 stream info AUDIT_STREAM
docker compose run --rm nats-bootstrap nats --server nats://nats:4222 consumer info AUDIT_STREAM zig-coordinator-scan
docker compose exec -T postgres psql -U sync -d sync -c "select status, count(*) from sync_scan_ingest group by status"
docker compose exec -T postgres psql -U sync -d sync -c "select count(*) from sync_job; select count(*) from sync_batch;"
```

For attribution, usernames come from the device registry. Passive wireless-only observations should remain `identity_source='unknown'` until a registered device record provides a reliable correlation such as `wg_pubkey`, claim token, hostname, or MAC hint.

### Device upsert response note

`DeviceUpsertResponse.claim_token` is now optional on device upsert responses.

- `claim_token` is returned (`Some`) only when a new device is created or when `regenerate_claim_token=true` is set on the request.
- For metadata-only updates to an existing device, `claim_token` is `None` and omitted from JSON (`skip_serializing_if = "Option::is_none"`).

Client migration guidance: treat `claim_token` as nullable/optional and only persist a new token when the field is present; do not assume every upsert response contains a token string.

---

### 8. Security Hardening Controls (Threat-Model Gap Closure)

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
