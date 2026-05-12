const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const logging = @import("logging.zig");
const nats = @import("nats.zig");
const nats_cli = @import("nats_cli.zig");

pub const BatchResult = struct {
    items: [][]const u8,
};

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
        "nats",            "--server", cfg.sync_nats_url,
        "consumer",        "next",     cfg.audit_stream_name,
        cfg.scan_consumer, "--count",  count_str,
        "--raw",
    };
    return pullNatsMessages(allocator, io, &argv);
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
        "nats",              "--server", cfg.sync_nats_url,
        "consumer",          "next",     cfg.result_stream_name,
        cfg.result_consumer, "--count",  count_str,
        "--raw",
    };
    return pullNatsMessages(allocator, io, &argv);
}

pub fn pullWirelessMessage(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    stream: []const u8,
    consumer: []const u8,
) Error!?[]u8 {
    const argv = [_][]const u8{
        "nats",     "--server", cfg.sync_nats_url,
        "consumer", "next",     stream,
        consumer,   "--count",  "1",
        "--raw",
    };

    var result = command.exec(allocator, io, &argv) catch return error.WirelessMessageFailed;
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        if (nats_cli.looksLikeNoMessage(result.stderr)) return null;
        command.logFailure("nats", result);
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
        "nats",     "--server", cfg.sync_nats_url,
        "consumer", "info",     stream,
        consumer,
    };

    var result = command.exec(allocator, io, &argv) catch return error.WirelessMessageFailed;
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("nats", result);
        return error.WirelessMessageFailed;
    }

    return nats_cli.consumerInfoHasBacklog(result.stdout);
}

pub fn publish(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    subject: []const u8,
    payload: []const u8,
    on_error: Error,
) Error!void {
    try publishWithMode(allocator, io, cfg, subject, payload, .core, on_error);
}

pub fn publishWithMode(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    subject: []const u8,
    payload: []const u8,
    mode: nats.PublishMode,
    on_error: Error,
) Error!void {
    nats.publish(allocator, io, cfg.sync_nats_url, subject, payload, mode, cfg.nats_publish_timeout_ms) catch |err| {
        if (err == error.UnsupportedNatsScheme and mode == .core) return publishWithCli(allocator, io, cfg, subject, payload, on_error);
        if (err == error.PublishAckFailed and mode == .core) return publishWithCli(allocator, io, cfg, subject, payload, on_error);
        if (err == error.UnsupportedNatsScheme and mode == .jetstream_ack) return publishWithJetStreamCli(allocator, io, cfg, subject, payload, on_error);
        if (err == error.PublishAckFailed and mode == .jetstream_ack) return publishWithJetStreamCli(allocator, io, cfg, subject, payload, on_error);

        logging.err()
            .stringSafe("event", "nats_publish_failure")
            .string("subject", subject)
            .err(err)
            .log();
        return on_error;
    };
}

fn pullNatsMessages(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) Error!BatchResult {
    var result = command.exec(allocator, io, argv) catch return BatchResult{ .items = &.{} };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        if (nats_cli.looksLikeNoMessage(result.stderr)) return BatchResult{ .items = &.{} };
        command.logFailure("nats", result);
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

fn publishWithJetStreamCli(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    subject: []const u8,
    payload: []const u8,
    on_error: Error,
) Error!void {
    logging.info()
        .stringSafe("event", "nats_publish_fallback")
        .stringSafe("mode", "jetstream_cli")
        .string("subject", subject)
        .log();
    const argv = [_][]const u8{ "nats", "--server", cfg.sync_nats_url, "pub", subject, payload };
    try runRequiredCommand(allocator, io, &argv, "nats", on_error);
}

fn publishWithCli(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    subject: []const u8,
    payload: []const u8,
    on_error: Error,
) Error!void {
    logging.info()
        .stringSafe("event", "nats_publish_fallback")
        .stringSafe("mode", "cli")
        .string("subject", subject)
        .log();
    const argv = [_][]const u8{ "nats", "--server", cfg.sync_nats_url, "pub", subject, payload };
    try runRequiredCommand(allocator, io, &argv, "nats", on_error);
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
