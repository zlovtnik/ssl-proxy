const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const logging = @import("logging.zig");
const redpanda_cli = @import("redpanda_cli.zig");
const topic_manifest = @import("topic_manifest.zig");

pub const Error = error{
    OutOfMemory,
    InvalidRedpandaUrl,
    RedpandaCheckFailed,
    RedpandaStreamMissing,
    RedpandaStreamTopicMissing,
    RedpandaConsumerMissing,
    RedpandaConsumerFilterMismatch,
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
    var topo = try topic_manifest.load(allocator, io, cfg.redpanda_topic_manifest_file);
    defer topo.deinit();

    for (topo.streams) |stream| {
        try checkRedpandaStream(allocator, io, cfg.sync_redpanda_url, stream.name);
        var topics = std.mem.splitScalar(u8, stream.topics_csv, ',');
        while (topics.next()) |raw_topic| {
            const topic = std.mem.trim(u8, raw_topic, " \t\r\n");
            if (topic.len == 0) continue;
            try checkRedpandaStreamTopic(allocator, io, cfg.sync_redpanda_url, stream.name, topic);
        }
    }
}

pub fn checkConsumers(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    var topo = try topic_manifest.load(allocator, io, cfg.redpanda_topic_manifest_file);
    defer topo.deinit();

    for (topo.consumers) |consumer| {
        try checkRedpandaConsumerFilter(allocator, io, cfg.sync_redpanda_url, consumer.stream_name, consumer.name, consumer.filter_topic);
    }
}

fn checkRedpandaStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    redpanda_url: []const u8,
    stream_name: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "redpanda",
        "--server",
        redpanda_url,
        "stream",
        "info",
        stream_name,
    };
    try runRequiredCommand(allocator, io, &argv, "redpanda", error.RedpandaStreamMissing);
}

fn checkRedpandaStreamTopic(
    allocator: std.mem.Allocator,
    io: std.Io,
    redpanda_url: []const u8,
    stream_name: []const u8,
    expected_topic: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "redpanda",
        "--server",
        redpanda_url,
        "stream",
        "info",
        stream_name,
        "--json",
    };

    var result = command.exec(allocator, io, &argv) catch {
        return error.RedpandaStreamMissing;
    };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("redpanda", result);
        return error.RedpandaStreamMissing;
    }

    if (!streamInfoHasTopic(allocator, result.stdout, expected_topic)) {
        logging.err()
            .stringSafe("event", "redpanda_stream_topic")
            .stringSafe("status", "error")
            .string("stream", stream_name)
            .string("expected_topic", expected_topic)
            .log();
        return error.RedpandaStreamTopicMissing;
    }
}

fn checkRedpandaConsumerFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    redpanda_url: []const u8,
    stream_name: []const u8,
    consumer_name: []const u8,
    expected_filter: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "redpanda",
        "--server",
        redpanda_url,
        "consumer",
        "info",
        stream_name,
        consumer_name,
        "--json",
    };

    var result = command.exec(allocator, io, &argv) catch {
        return error.RedpandaConsumerMissing;
    };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("redpanda", result);
        return error.RedpandaConsumerMissing;
    }

    if (!consumerInfoFilterMatches(allocator, result.stdout, expected_filter)) {
        logging.err()
            .stringSafe("event", "redpanda_consumer_filter")
            .stringSafe("status", "error")
            .string("stream", stream_name)
            .string("consumer", consumer_name)
            .string("expected_filter", expected_filter)
            .log();
        return error.RedpandaConsumerFilterMismatch;
    }
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

fn consumerInfoFilterMatches(
    allocator: std.mem.Allocator,
    stdout: []const u8,
    expected_filter: []const u8,
) bool {
    const ConsumerConfig = struct {
        filter_topic: ?[]const u8 = null,
    };
    const ConsumerInfo = struct {
        config: ConsumerConfig,
    };

    var parsed = std.json.parseFromSlice(ConsumerInfo, allocator, stdout, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();

    const actual = parsed.value.config.filter_topic orelse return false;
    return std.mem.eql(u8, actual, expected_filter);
}

fn streamInfoHasTopic(
    allocator: std.mem.Allocator,
    stdout: []const u8,
    expected_topic: []const u8,
) bool {
    const StreamConfig = struct {
        topics: []const []const u8 = &.{},
    };
    const StreamInfo = struct {
        config: StreamConfig,
    };

    var parsed = std.json.parseFromSlice(StreamInfo, allocator, stdout, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();

    for (parsed.value.config.topics) |topic| {
        if (topicPatternMatches(topic, expected_topic)) return true;
    }
    return false;
}

fn topicPatternMatches(pattern: []const u8, topic: []const u8) bool {
    if (std.mem.eql(u8, pattern, topic)) return true;

    var pattern_parts = std.mem.splitScalar(u8, pattern, '.');
    var topic_parts = std.mem.splitScalar(u8, topic, '.');

    while (pattern_parts.next()) |pattern_part| {
        if (std.mem.eql(u8, pattern_part, ">")) {
            return pattern_parts.next() == null and topic_parts.next() != null;
        }

        const topic_part = topic_parts.next() orelse return false;
        if (std.mem.eql(u8, pattern_part, "*")) continue;
        if (!std.mem.eql(u8, pattern_part, topic_part)) return false;
    }

    return topic_parts.next() == null;
}

test "consumerInfoFilterMatches validates consumer filter" {
    const json =
        \\{
        \\  "name": "oracle-worker-load",
        \\  "config": {
        \\    "filter_topic": "sync.oracle.load"
        \\  }
        \\}
    ;

    try std.testing.expect(consumerInfoFilterMatches(std.testing.allocator, json, "sync.oracle.load"));
    try std.testing.expect(!consumerInfoFilterMatches(std.testing.allocator, json, "wireless.audit"));
}

test "streamInfoHasTopic validates exact and wildcard topics" {
    const json =
        \\{
        \\  "config": {
        \\    "topics": ["sync.scan.request", "sync.oracle.load", "wireless.>"]
        \\  }
        \\}
    ;

    try std.testing.expect(streamInfoHasTopic(std.testing.allocator, json, "sync.oracle.load"));
    try std.testing.expect(streamInfoHasTopic(std.testing.allocator, json, "wireless.audit"));
    try std.testing.expect(!streamInfoHasTopic(std.testing.allocator, json, "sync.oracle.result"));
}

test "topicPatternMatches follows Redpanda wildcard shape" {
    try std.testing.expect(topicPatternMatches("sync.oracle.load", "sync.oracle.load"));
    try std.testing.expect(topicPatternMatches("sync.*.load", "sync.oracle.load"));
    try std.testing.expect(topicPatternMatches("sync.>", "sync.oracle.load"));
    try std.testing.expect(!topicPatternMatches("sync.*.load", "sync.oracle.result"));
    try std.testing.expect(!topicPatternMatches("sync.>", "sync"));
}
