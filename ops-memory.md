# Ops Memory

## Environment Matrix
- Server: `192.168.1.221`, Linux amd64, Docker Compose stack (`ssl-proxy`) hosting WireGuard/public UDP ingress.
- Linux test client: `192.168.1.68`, Linux host used for shim and local `wg-quick` validation.
- Mobile client: iPhone WireGuard app (no local shim process available).
- Primary tunnel CIDR: `10.13.13.0/24` with server `10.13.13.1` and peer `10.13.13.2`.

## Known Failure Signatures
- `magic_byte_mismatch`
Cause: Raw client traffic sent to obfuscation-enabled ingress.
Fix: For iPhone/direct mode, run with `WG_OBFUSCATION_ENABLED=false`.
Retry policy: auto-fix allowed once (runtime recreate).

- `RTNETLINK answers: Address already in use` during `wg-quick up`
Cause: Client `ListenPort=443` conflict with local service already bound to UDP/443.
Fix: Remove `ListenPort` or set a free port on that client profile.
Retry policy: manual.

- `RTNETLINK answers: No such device` on `ip -6 route add ::/0`
Cause: Client route setup failure for IPv6 default route.
Fix: Temporarily remove `::/0` from `AllowedIPs` (IPv4-only test path).
Retry policy: manual.

- Host-local admin health false-negative (`127.0.0.1:3002`)
Cause: Admin service bound to loopback inside container.
Fix: Treat in-container `/health` as authoritative fallback.
Retry policy: auto-handled.

- `Permission denied` while QR rendering peer configs
Cause: Root-owned config files synced by container.
Fix: Render QR from `/config/...` inside container when host file unreadable.
Retry policy: auto-handled.

- `lookup registry-1.docker.io ... i/o timeout`
Cause: Host DNS resolver outage/path failure.
Fix: Recover host DNS; if image exists locally, use `docker compose up -d --no-build --force-recreate`.
Retry policy: auto-fix allowed once (`--no-build` fallback).

## Last Known Good
- iPhone direct mode prerequisites:
  - `PROFILE_MODE=iphone`
  - Runtime obfuscation disabled (`wg_obfuscation_enabled=false`)
  - iPhone profile endpoint points to server LAN/public IP (`192.168.1.221:443`), not `127.0.0.1:51821`.
  - Confirm handshake on server: peer endpoint populated + recent handshake timestamp.

- Linux shim mode prerequisites:
  - `PROFILE_MODE=linux-shim`
  - Runtime obfuscation enabled (`wg_obfuscation_enabled=true`)
  - Local shim listening on client loopback (`127.0.0.1:51821`)
  - Shim forwards to server endpoint and key/magic settings match server.

## Incident Timeline
- 2026-04-17T00:00:00Z | result=fail | mode=linux-shim | signature=magic_byte_mismatch | action=switched server runtime for direct client test | context=server 192.168.1.221 amd64; client 192.168.1.68 iPhone | event=iPhone traffic reached obfuscated ingress and was dropped
- 2026-04-17T00:00:00Z | result=fail | mode=linux-shim | signature=wg_client_listenport_conflict | action=removed ListenPort from client profile | context=linux test client 192.168.1.68 | event=local client interface failed to come up with Address already in use
- 2026-04-17T00:00:00Z | result=fail | mode=linux-shim | signature=wg_client_ipv6_route_failure | action=removed ::/0 for ipv4-only verification | context=linux test client 192.168.1.68 | event=wg-quick failed adding ipv6 default route
- 2026-04-17T00:00:00Z | result=fail | mode=iphone | signature=admin_loopback_false_negative | action=added in-container health fallback | context=server 192.168.1.221 amd64 | event=up-ready looped on host admin endpoint while container was healthy
- 2026-04-17T00:00:00Z | result=fail | mode=iphone | signature=qr_permission_denied | action=rendered qr from container bind mount path | context=server 192.168.1.221 amd64 | event=qr generation failed on root-owned config file
- 2026-04-17T00:00:00Z | result=fail | mode=iphone | signature=docker_registry_dns_timeout | action=fallback no-build recreate | context=server 192.168.1.221 amd64 | event=compose build metadata pull failed during dns outage

## Open Risks
- CoreDNS upstream reachability may fail depending on host egress/DNS policy; browsing symptoms can mimic tunnel issues.
- Transparent fail-closed SNI policy can block application flows even with healthy handshakes.
- Running full-tunnel client profiles on the VPN server host can break host DNS/egress and cause misleading build/connectivity failures.
- 2026-04-18T12:52:11Z | result=fail | mode=iphone | server=192.168.1.221 | client=192.168.1.68 | arch=arm64 | signature=worker_wallet_missing | action=Mount wallet lib and secrets into oracle-worker only
- 2026-04-20T15:49:32Z | result=fail | mode=iphone | server=192.168.1.53 | client=192.168.1.68 | arch=arm64 | signature=unknown | action=Inspect diagnostics bundle
- 2026-04-20T15:52:10Z | result=fail | mode=iphone | server=192.168.1.53 | client=192.168.1.68 | arch=arm64 | signature=unknown | action=Inspect diagnostics bundle
- 2026-04-20T15:58:59Z | result=fail | mode=iphone | server=192.168.1.53 | client=192.168.1.68 | arch=arm64 | signature=unknown | action=Inspect diagnostics bundle
- 2026-04-21T21:40:23Z | result=fail | mode=iphone | server=192.168.1.221 | client=192.168.1.68 | arch=arm64 | signature=qr_permission_denied | action=Read profile from /config bind mount inside container
- 2026-04-21T21:40:50Z | result=fail | mode=iphone | server=192.168.1.221 | client=192.168.1.68 | arch=arm64 | signature=worker_wallet_missing | action=Mount wallet lib and secrets into oracle-worker only
