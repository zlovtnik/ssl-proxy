# System Architecture

## Runtime Data Plane

```mermaid
flowchart LR
    subgraph CLIENT
        CI
        CP
        CA
        CI --> CP --> CA
    end

    subgraph HOST
        HE
        HP
    end

    subgraph CONTAINER
        subgraph BOOT
            BT
            BR
            BQ
            BT --> BR --> BQ
        end

        subgraph WG
            WGI
            WGN
            WGM
            WGI --> WGN
            WGI --> WGM
        end

        subgraph DNS
            CD
            CU
            CD --> CU
        end

        subgraph TP
            TPL
            TPT
            TPR
            TPO
            TPL --> TPT --> TPR --> TPO
        end

        subgraph ADMIN
            AH
        end

        subgraph LEGACY
            LX
            LP
            LQ
            LN
            LX --> LP
            LX --> LQ
            LP --> LN
        end
    end

    subgraph ORIGIN
        O1
    end

    CP -->|"UDP 443 tunnel"| HE -->|"into container"| BQ
    WGI -->|"VPN client DNS queries"| CD
    CA -->|"All client traffic enters tunnel"| WGI
    WGN -->|"Redirect TCP 80/443"| TPL
    TPO -->|"Egress to origins"| O1
    WGM -->|"SNAT / return path"| O1
    HP --> AH

    style CLIENT fill:#e8f1ff,stroke:#4f46e5,stroke-width:2px
    style HOST fill:#eefbf2,stroke:#15803d,stroke-width:2px
    style CONTAINER fill:#fff7ed,stroke:#c2410c,stroke-width:2px
    style ORIGIN fill:#f5f3ff,stroke:#7c3aed,stroke-width:2px
```

### Legend

#### CLIENT
- `CI`: Client Interface
- `CP`: Client Protocol
- `CA`: Client Application

#### HOST
- `HE`: Host Endpoint
- `HP`: Host Port

#### CONTAINER

##### BOOT
- `BT`: Bootstrap Task
- `BR`: Bootstrap Runner
- `BQ`: Bootstrap Queue

##### WG
- `WGI`: WireGuard Ingress
- `WGN`: WireGuard NAT
- `WGM`: WireGuard Masquerade

##### DNS
- `CD`: CoreDNS
- `CU`: CoreDNS Upstream

##### TP
- `TPL`: Transparent Proxy Listener
- `TPT`: Transparent Proxy Transit
- `TPR`: Transparent Proxy Relay
- `TPO`: Transparent Proxy Origin

##### ADMIN
- `AH`: Admin Handler

##### LEGACY
- `LX`: Legacy Entry
- `LP`: Legacy Proxy Listener
- `LQ`: Legacy Queue
- `LN`: Legacy Network Path

#### ORIGIN
- `O1`: Origin Server

## Client Expectations

```mermaid
---
config:
  theme: neo
  themeVariables:
    fontSize: 14px
---
flowchart TD
    START(["🚀 Client Setup"]) --> IMPORT["📥 Import WireGuard Config\n<code>config/peer1/peer1-obfuscated.conf.example</code>"]
    IMPORT --> PROFILE["⚙️ Profile Configuration\n• Address: <code>10.13.13.2/32</code>\n• DNS: <code>10.13.13.1</code>\n• Endpoint: <code>127.0.0.1:51821</code>\n• AllowedIPs: <code>0.0.0.0/0, ::/0</code>"]
    PROFILE --> SHIM["🪄 Local `wg-obfs-shim`\nApplies XOR + optional magic byte\nForwards to server <code>:443</code>"]
    SHIM --> CONNECT["🔐 Establish Tunnel\nObfuscated UDP 443 → Docker host"]
    CONNECT --> ROUTE{"✅ Expected Behavior"}
    ROUTE --> DNS["🌐 DNS Resolution\nQueries route via VPN <code>10.13.13.1</code>\n(bypasses local ISP resolver)"]
    ROUTE --> WEB["🌍 Web Traffic\nTCP 80/443 intercepted at <code>wg0</code>\nProcessed by transparent proxy <code>:3001</code>\nUDP 443 dropped when strict enforcement is enabled"]
    ROUTE --> ADMIN["🔧 Admin Dashboard\nRemains host-local at <code>127.0.0.1:3002</code>\n(not exposed through tunnel)"]
    IMPORT --> NOHTTP["⚠️ No Manual HTTP Proxy"]
    NOHTTP --> WHY["ℹ️ Why?\nWireGuard is the primary client path\nExplicit proxy mode is optional"]
    WHY --> DEBUG["🐛 Debug Mode Only\n<code>EXPLICIT_PROXY_ENABLED=true</code>\nenables alternate proxy listeners"]

    classDef startNode fill:#3b82f6,stroke:#1e40af,stroke-width:3px,color:#fff
    classDef configNode fill:#10b981,stroke:#047857,stroke-width:2px,color:#fff
    classDef routeNode fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#000
    classDef warningNode fill:#ef4444,stroke:#b91c1c,stroke-width:2px,color:#fff
    classDef infoNode fill:#8b5cf6,stroke:#6d28d9,stroke-width:2px,color:#fff

    class START startNode
    class PROFILE,CONNECT configNode
    class ROUTE,DNS,WEB,ADMIN routeNode
    class NOHTTP,DEBUG warningNode
    class WHY infoNode
```

## Port Assignments

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| WireGuard VPN | 443 | UDP | External obfuscated tunnel endpoint |
| Transparent Proxy | 3001 | TCP | Internal listener for redirected WireGuard traffic |
| Admin API + Dashboard | 3002 | TCP | Internal health, dashboard, and stats surface |
| Explicit Proxy | 3000 | TCP | Legacy opt-in listener, disabled by default |

`tunnel_blocked` indicates a denied network flow, not a guarantee that the entire site or app failed. Independent allowed flows can still complete.

## Component Startup Order

1. **CoreDNS** - Initializes the VPN DNS resolver and forwards upstream over DNS-over-TLS
2. **BoringTun** - Creates `wg0` as a userspace WireGuard-compatible TUN interface and establishes the encrypted client path
3. **ssl-proxy** - Starts transparent interception, obfuscation, and audit logging for tunneled traffic

## Obfuscation Profiles

Traffic is normalized per domain classification to prevent fingerprinting.

### Active Profiles

- **fox-news**: Fox News domain family
- **fox-sports**: Fox Sports domain family

### Applied Modifications

**Request Headers**
✅ Removes `X-Forwarded-For`, `Via`, `Forwarded` proxy headers
✅ Strips `DNT`, `Sec-GPC` privacy signals
✅ Normalizes User-Agent to configured standard value

**Response Headers**
✅ Removes `X-Cache`, `X-Edge-IP`, `X-Served-By` CDN leak headers
✅ Preserves security headers (CSP, HSTS)

Domain matching supports wildcard subdomains and is case-insensitive.

---

## Quick Start

1. **Setup secrets:**
   ```bash
   mkdir -p secrets
   echo "your-oracle-password" > secrets/oracle_password.txt
   ```

2. **Start stack:**
   ```bash
   docker compose up -d
   ```

3. **WireGuard Client Configuration:**
   Build and run the bundled Linux `wg-obfs-shim`, then import `config/peer1/peer1-obfuscated.conf.example` into the WireGuard client. The profile endpoint `127.0.0.1:51821` is local to the client machine; configure the real remote server endpoint separately in `config/client/wg-obfs-shim.env.example`. Do not combine this with a separate manual HTTP proxy on the client.

   Verify the service locally:
   ```bash
   curl -i http://127.0.0.1:3002/health
   ```

## Legacy Explicit Proxy Mode

The explicit HTTP/HTTPS proxy path is retained only for controlled debugging. It must be enabled explicitly with `EXPLICIT_PROXY_ENABLED=true`, and plaintext HTTP proxy mode still exposes `CONNECT host:443` metadata on the client-to-proxy leg.
