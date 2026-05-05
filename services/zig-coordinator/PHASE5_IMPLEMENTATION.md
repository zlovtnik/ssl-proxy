# Phase 5 Implementation: Wireless Subject Handlers

## Overview
Extended zig-coordinator to handle 7 new NATS subjects for wireless operations, following the existing drainScanRequests/handleResults pattern.

## Changes Made

### 1. Database Functions (`src/postgres/schema.sql`)

Added 7 new PostgreSQL functions in the `coordinator` schema:

#### `coordinator.save_backlog_entry(p_payload jsonb)`
- **Subject**: `wireless.backlog.save`
- **Purpose**: Upserts audit_backlog entries
- **Behavior**: Inserts new entry or updates existing to 'pending' status

#### `coordinator.list_pending_backlog()`
- **Subject**: `wireless.backlog.list` (request/reply)
- **Purpose**: Returns pending audit_backlog rows as JSON array
- **Limit**: 100 rows, ordered by created_at

#### `coordinator.mark_backlog_synced(p_dedupe_key text)`
- **Subject**: `wireless.backlog.synced`
- **Purpose**: Updates audit_backlog status to 'synced'

#### `coordinator.prune_backlog()`
- **Subject**: `wireless.backlog.prune`
- **Purpose**: Deletes synced entries older than 7 days
- **Returns**: Count of deleted rows

#### `coordinator.lookup_device_by_mac(p_mac text)`
- **Subject**: `wireless.mac.lookup` (request/reply)
- **Purpose**: Queries devices table by MAC address
- **Returns**: JSON object with device_id, username, display_name, hostname or null

#### `coordinator.list_authorized_networks()`
- **Subject**: `wireless.networks.authorized` (request/reply + push)
- **Purpose**: Returns all enabled authorized_wireless_networks
- **Returns**: JSON array with ssid, bssid (lowercase), location_id, label, enabled

#### `coordinator.flush_probe_batch(p_probes jsonb)`
- **Subject**: `wireless.probe.flush`
- **Purpose**: Batch upserts network_clients from probe accumulator
- **Behavior**: Looks up known_bssid from authorized_wireless_networks, increments probe_count on conflict

### 2. Database Client Methods (`src/db.zig`)

Added 6 new public methods to `db.Client`:

- `saveBacklogEntry(payload_json: []const u8) Error!void`
- `listPendingBacklog() Error!?[]u8`
- `markBacklogSynced(dedupe_key: []const u8) Error!void`
- `pruneBacklog() Error!?[]u8`
- `lookupDeviceByMac(mac: []const u8) Error!?[]u8`
- `listAuthorizedNetworks() Error!?[]u8`
- `flushProbeBatch(probes_json: []const u8) Error!void`

Added 4 new error types:
- `BacklogOperationFailed`
- `MacLookupFailed`
- `NetworksListFailed`
- `ProbeFlushFailed`

### 3. Scheduler Handlers (`src/scheduler.zig`)

#### Extended `runIteration()` Loop
Added 7 new handler calls after existing handlers:
```zig
had_work = (try self.handleBacklogSave()) or had_work;
had_work = (try self.handleBacklogList()) or had_work;
had_work = (try self.handleBacklogSynced()) or had_work;
had_work = (try self.handleBacklogPrune()) or had_work;
had_work = (try self.handleMacLookup()) or had_work;
had_work = (try self.handleNetworksAuthorized()) or had_work;
had_work = (try self.handleProbeFlush()) or had_work;
```

#### New Handler Methods
Each handler follows the same pattern:
1. Pull message from NATS consumer via `pullWirelessMessage()`
2. Parse JSON if needed
3. Call corresponding database method
4. Publish reply for request/reply subjects
5. Log success/error with structured logging
6. Return `true` if work was done, `false` otherwise

#### Helper Method
- `pullWirelessMessage(stream: []const u8, consumer: []const u8) Error!?[]u8`
  - Wraps NATS consumer pull logic
  - Returns null if no message available
  - Handles "no messages" timeout gracefully

#### Error Types Added
- `BacklogOperationFailed`
- `MacLookupFailed`
- `NetworksListFailed`
- `ProbeFlushFailed`
- `WirelessMessageFailed`

## NATS Consumer Configuration Required

The following NATS streams and consumers must be created:

### Streams
- `WIRELESS_BACKLOG_STREAM` - for backlog operations
- `WIRELESS_MAC_STREAM` - for MAC lookup requests
- `WIRELESS_NETWORKS_STREAM` - for authorized networks requests
- `WIRELESS_PROBE_STREAM` - for probe flush operations

### Consumers
- `wireless-backlog-save` on `WIRELESS_BACKLOG_STREAM`
- `wireless-backlog-list` on `WIRELESS_BACKLOG_STREAM`
- `wireless-backlog-synced` on `WIRELESS_BACKLOG_STREAM`
- `wireless-backlog-prune` on `WIRELESS_BACKLOG_STREAM`
- `wireless-mac-lookup` on `WIRELESS_MAC_STREAM`
- `wireless-networks-authorized` on `WIRELESS_NETWORKS_STREAM`
- `wireless-probe-flush` on `WIRELESS_PROBE_STREAM`

## Subject Mapping

| Subject | Type | Handler | Database Function |
|---------|------|---------|-------------------|
| `wireless.backlog.save` | Fire-and-forget | `handleBacklogSave()` | `save_backlog_entry()` |
| `wireless.backlog.list` | Request/Reply | `handleBacklogList()` | `list_pending_backlog()` |
| `wireless.backlog.synced` | Fire-and-forget | `handleBacklogSynced()` | `mark_backlog_synced()` |
| `wireless.backlog.prune` | Fire-and-forget | `handleBacklogPrune()` | `prune_backlog()` |
| `wireless.mac.lookup` | Request/Reply | `handleMacLookup()` | `lookup_device_by_mac()` |
| `wireless.networks.authorized` | Request/Reply | `handleNetworksAuthorized()` | `list_authorized_networks()` |
| `wireless.probe.flush` | Fire-and-forget | `handleProbeFlush()` | `flush_probe_batch()` |

## Testing

Build verification:
```bash
cd /Users/rcs/git/ssl-proxy/services/zig-coordinator
zig build
```

Status: ✅ **Build successful**

## Integration Points

### Sensor → Coordinator
- Sensor publishes to `wireless.backlog.save`, `wireless.backlog.synced`, `wireless.probe.flush`
- Sensor requests via `wireless.backlog.list`, `wireless.mac.lookup`, `wireless.networks.authorized`

### Coordinator → Database
- All operations use PostgreSQL functions in `coordinator` schema
- Follows existing pattern: psql CLI invocation with SQL literal escaping

### Coordinator → Sensor (Replies)
- `wireless.backlog.list.reply` - JSON array of pending backlog entries
- `wireless.mac.lookup.reply` - JSON object or "null"
- `wireless.networks.authorized.reply` - JSON array of authorized networks

## Logging

All handlers emit structured logs with:
- `event` - operation name (e.g., "backlog_save", "mac_lookup")
- `status` - "ok" or "error"
- Additional context fields (dedupe_key, mac, payload_bytes, deleted_count, found)
- Error details on failure

## Performance Characteristics

- Each handler processes 1 message per iteration
- No batching (follows existing pattern)
- Handlers run sequentially in runIteration loop
- Database operations use psql CLI (consistent with existing code)
- Graceful handling of empty queues (returns false, no sleep)

## Future Enhancements

Potential optimizations (not implemented):
- Batch processing for probe flush (currently 1 message at a time)
- Connection pooling for database operations
- Native NATS client instead of CLI
- Caching for authorized networks list
- Push notifications for network config changes
