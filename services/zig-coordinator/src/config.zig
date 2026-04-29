const std = @import("std");

pub const Config = struct {
    stream_name: []const u8,
    stream_names_csv: []const u8,
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
    scan_max_attempts: u32,
    scan_retry_backoff_seconds: u32,
};

pub fn load() Config {
    return .{
        .stream_name = envOrDefault("SYNC_STREAM_NAME", "proxy.events"),
        .stream_names_csv = envOrDefault("SYNC_STREAM_NAMES", "proxy.events,wireless.audit"),
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
        .scan_max_attempts = parsePositiveU32(envOrDefault("SYNC_SCAN_MAX_ATTEMPTS", "5"), 5),
        .scan_retry_backoff_seconds = parsePositiveU32(envOrDefault("SYNC_SCAN_RETRY_BACKOFF_SECONDS", "30"), 30),
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
