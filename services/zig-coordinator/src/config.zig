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
    scan_consumer: []const u8,
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
        .sync_schema_file = envOrDefault("SYNC_SCHEMA_FILE", "/app/schema/postgres.sql"),
        .audit_stream_name = envOrDefault("AUDIT_STREAM_NAME", "AUDIT_STREAM"),
        .scan_consumer = envOrDefault("SYNC_SCAN_CONSUMER", "zig-coordinator-scan"),
    };
}

fn envOrDefault(comptime name: [:0]const u8, default_value: []const u8) []const u8 {
    return if (std.c.getenv(name)) |value| std.mem.span(value) else default_value;
}

fn parseBatchSize(value: []const u8) usize {
    return std.fmt.parseInt(usize, value, 10) catch 100;
}
