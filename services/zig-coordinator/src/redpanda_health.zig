const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const logging = @import("logging.zig");
const redpanda_cli = @import("redpanda_cli.zig");

pub const Error = error{
    OutOfMemory,
    InvalidRedpandaUrl,
    RedpandaCheckFailed,
    RedpandaTopicMissing,
    TopologyFileMissing,
    TopologyParseFailed,
};

pub fn checkConnectivity(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    const authority = try redpanda_cli.parseRedpandaAuthority(allocator, cfg.sync_redpanda_url);
    defer allocator.free(authority);

    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    const separator = std.mem.lastIndexOfScalar(u8, host_and_port, ':') orelse return error.InvalidRedpandaUrl;
    const host = host_and_port[0..separator];
    const port = host_and_port[separator + 1 ..];
    if (host.len == 0 or port.len == 0) return error.InvalidRedpandaUrl;

    const argv = [_][]const u8{
        "nc",
        "-z",
        host,
        port,
    };
    try runRequiredCommand(allocator, io, &argv, "nc", error.RedpandaCheckFailed);
}

pub fn checkStreams(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    const manifest = std.Io.Dir.cwd().readFileAlloc(io, cfg.redpanda_topic_manifest_file, allocator, .limited(1024 * 1024)) catch {
        return error.TopologyFileMissing;
    };
    defer allocator.free(manifest);

    var topics = std.mem.splitScalar(u8, manifest, '\n');
    while (topics.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0 or std.mem.startsWith(u8, line, "#")) continue;

        var fields = std.mem.splitScalar(u8, line, '|');
        const topic = std.mem.trim(u8, fields.first(), " \t\r\n");
        if (topic.len == 0) return error.TopologyParseFailed;
        try checkRedpandaTopic(allocator, io, cfg.sync_redpanda_url, topic);
    }
}

pub fn checkConsumers(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    _ = allocator;
    _ = io;
    _ = cfg;
    // Redpanda/Kafka consumer groups are created by consumers at runtime; there
    // is no durable-consumer topology to validate before the services start.
}

fn checkRedpandaTopic(
    allocator: std.mem.Allocator,
    io: std.Io,
    redpanda_url: []const u8,
    topic: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "rpk",
        "topic",
        "describe",
        topic,
        "--brokers",
        redpanda_url,
    };
    runRequiredCommand(allocator, io, &argv, "rpk", error.RedpandaTopicMissing) catch |err| {
        logging.err()
            .stringSafe("event", "redpanda_topic")
            .stringSafe("status", "error")
            .string("topic", topic)
            .log();
        return err;
    };
}

fn runRequiredCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    command_name: []const u8,
    on_error: Error,
) Error!void {
    var result = command.exec(allocator, io, argv) catch {
        return on_error;
    };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure(command_name, result);
        return on_error;
    }

    command.logOutput(command_name, result.stdout);
}

test "checkConsumers is a Redpanda no-op" {
    try checkConsumers(std.testing.allocator, .default, .{
        .stream_name = "",
        .stream_names_csv = "",
        .oracle_stream_names_csv = "",
        .batch_size = 1,
        .scan_topic = "",
        .load_topic = "",
        .result_topic = "",
        .database_url = "",
        .sync_redpanda_url = "",
        .redpanda_topic_manifest_file = "",
        .sync_schema_file = "",
        .audit_stream_name = "",
        .result_stream_name = "",
        .scan_consumer = "",
        .load_consumer = "",
        .result_consumer = "",
        .wireless_backlog_stream_name = "",
        .wireless_mac_stream_name = "",
        .wireless_networks_stream_name = "",
        .wireless_probe_stream_name = "",
        .wireless_backlog_save_consumer = "",
        .wireless_backlog_list_consumer = "",
        .wireless_backlog_synced_consumer = "",
        .wireless_backlog_prune_consumer = "",
        .wireless_mac_lookup_consumer = "",
        .wireless_networks_authorized_consumer = "",
        .wireless_probe_flush_consumer = "",
        .wireless_backlog_list_reply_topic = "",
        .wireless_backlog_prune_reply_topic = "",
        .wireless_mac_lookup_reply_topic = "",
        .wireless_networks_authorized_reply_topic = "",
        .sync_outbox_dir = "",
        .scan_max_attempts = 1,
        .scan_retry_backoff_seconds = 1,
        .batch_dispatch_lease_seconds = 1,
        .batch_max_attempts = 1,
        .redpanda_publish_timeout_ms = 1,
        .scan_fetch_count = 1,
        .result_fetch_count = 1,
        .ingest_batch_size = 1,
        .dispatch_batch_size = 1,
    });
}
