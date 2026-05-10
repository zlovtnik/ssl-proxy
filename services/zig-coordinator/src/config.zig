const std = @import("std");

pub const Config = struct {
    stream_name: []const u8,
    stream_names_csv: []const u8,
    oracle_stream_names_csv: []const u8,
    batch_size: usize,
    scan_subject: []const u8,
    load_subject: []const u8,
    result_subject: []const u8,
    database_url: []const u8,
    sync_nats_url: []const u8,
    sync_schema_file: []const u8,
    audit_stream_name: []const u8,
    result_stream_name: []const u8,
    scan_consumer: []const u8,
    load_consumer: []const u8,
    result_consumer: []const u8,
    wireless_backlog_stream_name: []const u8,
    wireless_mac_stream_name: []const u8,
    wireless_networks_stream_name: []const u8,
    wireless_probe_stream_name: []const u8,
    wireless_backlog_save_consumer: []const u8,
    wireless_backlog_list_consumer: []const u8,
    wireless_backlog_synced_consumer: []const u8,
    wireless_backlog_prune_consumer: []const u8,
    wireless_mac_lookup_consumer: []const u8,
    wireless_networks_authorized_consumer: []const u8,
    wireless_probe_flush_consumer: []const u8,
    wireless_backlog_list_reply_subject: []const u8,
    wireless_backlog_prune_reply_subject: []const u8,
    wireless_mac_lookup_reply_subject: []const u8,
    wireless_networks_authorized_reply_subject: []const u8,
    sync_outbox_dir: []const u8,
    scan_max_attempts: u32,
    scan_retry_backoff_seconds: u32,
    batch_dispatch_lease_seconds: u32,
    batch_max_attempts: u32,
    nats_publish_timeout_ms: u32,

    // Batch tuning knobs for high-throughput consumption
    scan_fetch_count: usize,
    result_fetch_count: usize,
    ingest_batch_size: u32,
    dispatch_batch_size: u32,
};

pub fn load() Config {
    return .{
        .stream_name = envOrDefault("SYNC_STREAM_NAME", "proxy.events"),
        .stream_names_csv = envOrDefault("SYNC_STREAM_NAMES", "proxy.events,wireless.audit"),
        .oracle_stream_names_csv = envOrDefault("SYNC_ORACLE_STREAM_NAMES", "proxy.events"),
        .batch_size = parseBatchSize(envOrDefault("SYNC_BATCH_SIZE", "100")),
        .scan_subject = envOrDefault("SYNC_SCAN_SUBJECT", "sync.scan.request"),
        .load_subject = envOrDefault("SYNC_LOAD_SUBJECT", "sync.oracle.load"),
        .result_subject = envOrDefault("SYNC_RESULT_SUBJECT", "sync.oracle.result"),
        .database_url = envOrDefault("DATABASE_URL", ""),
        .sync_nats_url = envOrDefault("SYNC_NATS_URL", ""),
        .sync_schema_file = envOrDefault("SYNC_SCHEMA_FILE", "/app/src/postgres/schema.sql"),
        .audit_stream_name = envOrDefault("AUDIT_STREAM_NAME", "AUDIT_STREAM"),
        .result_stream_name = envOrDefault("SYNC_RESULT_STREAM_NAME", "ORACLE_RESULT_STREAM"),
        .scan_consumer = envOrDefault("SYNC_SCAN_CONSUMER", "zig-coordinator-scan"),
        .load_consumer = envOrDefault("SYNC_LOAD_CONSUMER", "oracle-worker-load"),
        .result_consumer = envOrDefault("SYNC_RESULT_CONSUMER", "zig-coordinator-result"),
        .wireless_backlog_stream_name = envOrDefault("WIRELESS_BACKLOG_STREAM_NAME", "WIRELESS_BACKLOG_STREAM"),
        .wireless_mac_stream_name = envOrDefault("WIRELESS_MAC_STREAM_NAME", "WIRELESS_MAC_STREAM"),
        .wireless_networks_stream_name = envOrDefault("WIRELESS_NETWORKS_STREAM_NAME", "WIRELESS_NETWORKS_STREAM"),
        .wireless_probe_stream_name = envOrDefault("WIRELESS_PROBE_STREAM_NAME", "WIRELESS_PROBE_STREAM"),
        .wireless_backlog_save_consumer = envOrDefault("WIRELESS_BACKLOG_SAVE_CONSUMER", "wireless-backlog-save"),
        .wireless_backlog_list_consumer = envOrDefault("WIRELESS_BACKLOG_LIST_CONSUMER", "wireless-backlog-list"),
        .wireless_backlog_synced_consumer = envOrDefault("WIRELESS_BACKLOG_SYNCED_CONSUMER", "wireless-backlog-synced"),
        .wireless_backlog_prune_consumer = envOrDefault("WIRELESS_BACKLOG_PRUNE_CONSUMER", "wireless-backlog-prune"),
        .wireless_mac_lookup_consumer = envOrDefault("WIRELESS_MAC_LOOKUP_CONSUMER", "wireless-mac-lookup"),
        .wireless_networks_authorized_consumer = envOrDefault("WIRELESS_NETWORKS_AUTHORIZED_CONSUMER", "wireless-networks-authorized"),
        .wireless_probe_flush_consumer = envOrDefault("WIRELESS_PROBE_FLUSH_CONSUMER", "wireless-probe-flush"),
        .wireless_backlog_list_reply_subject = envOrDefault("WIRELESS_BACKLOG_LIST_REPLY_SUBJECT", "wireless.backlog.list.reply"),
        .wireless_backlog_prune_reply_subject = envOrDefault("WIRELESS_BACKLOG_PRUNE_REPLY_SUBJECT", "wireless.backlog.prune.reply"),
        .wireless_mac_lookup_reply_subject = envOrDefault("WIRELESS_MAC_LOOKUP_REPLY_SUBJECT", "wireless.mac.lookup.reply"),
        .wireless_networks_authorized_reply_subject = envOrDefault("WIRELESS_NETWORKS_AUTHORIZED_REPLY_SUBJECT", "wireless.networks.authorized.reply"),
        .sync_outbox_dir = envOrDefault("SYNC_OUTBOX_DIR", "/sync-outbox"),
        .scan_max_attempts = parsePositiveU32(envOrDefault("SYNC_SCAN_MAX_ATTEMPTS", "5"), 5),
        .scan_retry_backoff_seconds = parsePositiveU32(envOrDefault("SYNC_SCAN_RETRY_BACKOFF_SECONDS", "30"), 30),
        .batch_dispatch_lease_seconds = parsePositiveU32(envOrDefault("SYNC_BATCH_DISPATCH_LEASE_SECONDS", "300"), 300),
        .batch_max_attempts = parsePositiveU32(envOrDefault("SYNC_BATCH_MAX_ATTEMPTS", "5"), 5),
        .nats_publish_timeout_ms = parsePositiveU32(envOrDefault("NATS_PUBLISH_TIMEOUT_MS", "10000"), 10_000),

        // Batch tuning (env overridable)
        // Increased from 200→200 (scan), 200→200 (result), 200→200 (ingest), 5→200 (dispatch)
        .scan_fetch_count = parsePositiveUsize(envOrDefault("SYNC_SCAN_FETCH_COUNT", "200"), 200),
        .result_fetch_count = parsePositiveUsize(envOrDefault("SYNC_RESULT_FETCH_COUNT", "200"), 200),
        .ingest_batch_size = parsePositiveU32(envOrDefault("SYNC_INGEST_BATCH_SIZE", "200"), 200),
        .dispatch_batch_size = parsePositiveU32(envOrDefault("SYNC_DISPATCH_BATCH_SIZE", "500"), 500),
    };
}

fn envOrDefault(comptime name: [:0]const u8, default_value: []const u8) []const u8 {
    return if (std.c.getenv(name)) |value| std.mem.span(value) else default_value;
}

fn parseBatchSize(value: []const u8) usize {
    const parsed = std.fmt.parseInt(usize, value, 10) catch {
        std.debug.panic("SYNC_BATCH_SIZE must be a valid positive integer: {s}", .{value});
    };
    if (parsed == 0) {
        std.debug.panic("SYNC_BATCH_SIZE must be > 0: {s}", .{value});
    }
    return parsed;
}

fn parsePositiveU32(value: []const u8, default_value: u32) u32 {
    const parsed = std.fmt.parseInt(u32, value, 10) catch return default_value;
    return if (parsed == 0) default_value else parsed;
}

fn parsePositiveUsize(value: []const u8, default_value: usize) usize {
    const parsed = std.fmt.parseInt(usize, value, 10) catch return default_value;
    return if (parsed == 0) default_value else parsed;
}
