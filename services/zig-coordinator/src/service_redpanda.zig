const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const logging = @import("logging.zig");
const redpanda = @import("redpanda.zig");
const redpanda_cli = @import("redpanda_cli.zig");

pub const BatchResult = struct {
    items: [][]const u8,
};

pub fn freeBatch(allocator: std.mem.Allocator, batch: BatchResult) void {
    if (batch.items.len == 0) return;
    for (batch.items) |item| allocator.free(item);
    allocator.free(batch.items);
}

pub const Error = error{
    OutOfMemory,
    WirelessMessageFailed,
    AlertPublishFailed,
    BatchDispatchFailed,
};

pub fn pullScanBatch(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    count: usize,
) Error!BatchResult {
    const count_str = try std.fmt.allocPrint(allocator, "{d}", .{count});
    defer allocator.free(count_str);

    const argv = [_][]const u8{
        "redpanda",            "--server", cfg.sync_redpanda_url,
        "consumer",        "next",     cfg.audit_stream_name,
        cfg.scan_consumer, "--count",  count_str,
        "--raw",
    };
    return pullRedpandaMessages(allocator, io, &argv);
}

pub fn pullResultBatch(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    count: usize,
) Error!BatchResult {
    const count_str = try std.fmt.allocPrint(allocator, "{d}", .{count});
    defer allocator.free(count_str);

    const argv = [_][]const u8{
        "redpanda",              "--server", cfg.sync_redpanda_url,
        "consumer",          "next",     cfg.result_stream_name,
        cfg.result_consumer, "--count",  count_str,
        "--raw",
    };
    return pullRedpandaMessages(allocator, io, &argv);
}

pub fn pullWirelessMessage(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    stream: []const u8,
    consumer: []const u8,
) Error!?[]u8 {
    const argv = [_][]const u8{
        "redpanda",     "--server", cfg.sync_redpanda_url,
        "consumer", "next",     stream,
        consumer,   "--count",  "1",
        "--raw",
    };

    var result = command.exec(allocator, io, &argv) catch return error.WirelessMessageFailed;
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        if (redpanda_cli.looksLikeNoMessage(result.stderr)) return null;
        command.logFailure("redpanda", result);
        return error.WirelessMessageFailed;
    }

    const output = command.trimmedOutput(result.stdout);
    if (output.len == 0) return null;
    return allocator.dupe(u8, output) catch error.WirelessMessageFailed;
}

pub fn wirelessConsumerHasBacklog(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    stream: []const u8,
    consumer: []const u8,
) Error!bool {
    const argv = [_][]const u8{
        "redpanda",     "--server", cfg.sync_redpanda_url,
        "consumer", "info",     stream,
        consumer,
    };

    var result = command.exec(allocator, io, &argv) catch return error.WirelessMessageFailed;
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("redpanda", result);
        return error.WirelessMessageFailed;
    }

    return redpanda_cli.consumerInfoHasBacklog(result.stdout);
}

pub fn publish(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    topic: []const u8,
    payload: []const u8,
    on_error: Error,
) Error!void {
    try publishWithMode(allocator, io, cfg, topic, payload, .core, on_error);
}

pub fn publishWithMode(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    topic: []const u8,
    payload: []const u8,
    mode: redpanda.PublishMode,
    on_error: Error,
) Error!void {
    if (shouldUseRedpandaCliFirst(cfg.sync_redpanda_url)) {
        return publishWithCliFallback(allocator, io, cfg, topic, payload, mode, "redpanda_bootstrap", on_error);
    }

    redpanda.publish(allocator, io, cfg.sync_redpanda_url, topic, payload, mode, cfg.redpanda_publish_timeout_ms) catch |err| {
        if (shouldFallbackToRedpandaCli(err)) return publishWithCliFallback(allocator, io, cfg, topic, payload, mode, @errorName(err), on_error);

        logging.err()
            .stringSafe("event", "redpanda_publish_failure")
            .string("topic", topic)
            .err(err)
            .log();
        return on_error;
    };
}

fn pullRedpandaMessages(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) Error!BatchResult {
    var result = command.exec(allocator, io, argv) catch return BatchResult{ .items = &.{} };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        if (redpanda_cli.looksLikeNoMessage(result.stderr)) return BatchResult{ .items = &.{} };
        command.logFailure("redpanda", result);
        return BatchResult{ .items = &.{} };
    }

    const output = command.trimmedOutput(result.stdout);
    if (output.len == 0) return BatchResult{ .items = &.{} };

    var line_count: usize = 0;
    var count_iter = std.mem.splitScalar(u8, output, '\n');
    while (count_iter.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r\n").len > 0) line_count += 1;
    }
    if (line_count == 0) return BatchResult{ .items = &.{} };

    var items = try allocator.alloc([]const u8, line_count);
    errdefer {
        for (items) |item| allocator.free(item);
        allocator.free(items);
    }

    var idx: usize = 0;
    var iter = std.mem.splitScalar(u8, output, '\n');
    while (iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;
        items[idx] = try allocator.dupe(u8, line);
        idx += 1;
    }

    return BatchResult{ .items = items[0..idx] };
}

fn shouldFallbackToRedpandaCli(err: anyerror) bool {
    return err != error.InvalidTopic and err != error.OutOfMemory;
}

fn shouldUseRedpandaCliFirst(redpanda_url: []const u8) bool {
    const trimmed = std.mem.trim(u8, redpanda_url, " \t\r\n");
    return std.mem.startsWith(u8, trimmed, "redpanda://") or
        std.mem.indexOf(u8, trimmed, ":9092") != null or
        std.mem.indexOf(u8, trimmed, ":19092") != null or
        std.mem.indexOfScalar(u8, trimmed, ',') != null;
}

fn publishWithCliFallback(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    topic: []const u8,
    payload: []const u8,
    mode: redpanda.PublishMode,
    reason: []const u8,
    on_error: Error,
) Error!void {
    const fallback_mode = switch (mode) {
        .core => "cli",
        .redpanda_ack => "redpanda_cli",
    };
    logging.info()
        .stringSafe("event", "redpanda_publish_fallback")
        .stringSafe("mode", fallback_mode)
        .string("topic", topic)
        .stringSafe("reason", reason)
        .log();

    const server = redpanda_cli.parseRedpandaAuthority(allocator, cfg.sync_redpanda_url) catch return on_error;
    defer allocator.free(server);

    const argv = [_][]const u8{ "redpanda", "--server", server, "pub", topic, payload };
    try runRequiredCommand(allocator, io, &argv, "redpanda", on_error);
}

fn runRequiredCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    command_name: []const u8,
    on_error: Error,
) Error!void {
    var result = command.exec(allocator, io, argv) catch return on_error;
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure(command_name, result);
        return on_error;
    }

    command.logOutput(command_name, result.stdout);
}

test "native Redpanda publish failures fall back to the CLI producer" {
    try std.testing.expect(shouldFallbackToRedpandaCli(error.ReadFailed));
    try std.testing.expect(shouldFallbackToRedpandaCli(error.ProtocolError));
    try std.testing.expect(shouldFallbackToRedpandaCli(error.PublishAckFailed));
    try std.testing.expect(shouldFallbackToRedpandaCli(error.UnsupportedRedpandaScheme));
}

test "native Redpanda publish validation errors do not fall back to the CLI producer" {
    try std.testing.expect(!shouldFallbackToRedpandaCli(error.InvalidTopic));
    try std.testing.expect(!shouldFallbackToRedpandaCli(error.OutOfMemory));
}

test "Redpanda bootstrap addresses use the CLI producer first" {
    try std.testing.expect(shouldUseRedpandaCliFirst("redpanda:9092"));
    try std.testing.expect(shouldUseRedpandaCliFirst("redpanda://127.0.0.1:19092"));
    try std.testing.expect(shouldUseRedpandaCliFirst("redpanda-1:9092,redpanda-2:9092"));
    try std.testing.expect(!shouldUseRedpandaCliFirst("localhost:4222"));
}
