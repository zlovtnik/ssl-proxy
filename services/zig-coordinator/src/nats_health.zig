const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const logging = @import("logging.zig");
const nats_cli = @import("nats_cli.zig");
const topology = @import("topology.zig");

pub const Error = error{
    OutOfMemory,
    InvalidNatsUrl,
    NatsCheckFailed,
    NatsStreamMissing,
    NatsStreamSubjectMissing,
    NatsConsumerMissing,
    NatsConsumerFilterMismatch,
    TopologyFileMissing,
    TopologyParseFailed,
};

pub fn checkConnectivity(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    const authority = try nats_cli.parseNatsAuthority(allocator, cfg.sync_nats_url);
    defer allocator.free(authority);

    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    const separator = std.mem.lastIndexOfScalar(u8, host_and_port, ':') orelse return error.InvalidNatsUrl;
    const host = host_and_port[0..separator];
    const port = host_and_port[separator + 1 ..];
    if (host.len == 0 or port.len == 0) return error.InvalidNatsUrl;

    const argv = [_][]const u8{
        "nc",
        "-z",
        host,
        port,
    };
    try runRequiredCommand(allocator, io, &argv, "nc", error.NatsCheckFailed);
}

pub fn checkStreams(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    var topo = try topology.load(allocator, io, cfg.nats_topology_file);
    defer topo.deinit();

    for (topo.streams) |stream| {
        try checkNatsStream(allocator, io, cfg.sync_nats_url, stream.name);
        var subjects = std.mem.splitScalar(u8, stream.subjects_csv, ',');
        while (subjects.next()) |raw_subject| {
            const subject = std.mem.trim(u8, raw_subject, " \t\r\n");
            if (subject.len == 0) continue;
            try checkNatsStreamSubject(allocator, io, cfg.sync_nats_url, stream.name, subject);
        }
    }
}

pub fn checkConsumers(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) Error!void {
    var topo = try topology.load(allocator, io, cfg.nats_topology_file);
    defer topo.deinit();

    for (topo.consumers) |consumer| {
        try checkNatsConsumerFilter(allocator, io, cfg.sync_nats_url, consumer.stream_name, consumer.name, consumer.filter_subject);
    }
}

fn checkNatsStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    nats_url: []const u8,
    stream_name: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "nats",
        "--server",
        nats_url,
        "stream",
        "info",
        stream_name,
    };
    try runRequiredCommand(allocator, io, &argv, "nats", error.NatsStreamMissing);
}

fn checkNatsStreamSubject(
    allocator: std.mem.Allocator,
    io: std.Io,
    nats_url: []const u8,
    stream_name: []const u8,
    expected_subject: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "nats",
        "--server",
        nats_url,
        "stream",
        "info",
        stream_name,
        "--json",
    };

    var result = command.exec(allocator, io, &argv) catch {
        return error.NatsStreamMissing;
    };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("nats", result);
        return error.NatsStreamMissing;
    }

    if (!streamInfoHasSubject(allocator, result.stdout, expected_subject)) {
        logging.err()
            .stringSafe("event", "nats_stream_subject")
            .stringSafe("status", "error")
            .string("stream", stream_name)
            .string("expected_subject", expected_subject)
            .log();
        return error.NatsStreamSubjectMissing;
    }
}

fn checkNatsConsumerFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    nats_url: []const u8,
    stream_name: []const u8,
    consumer_name: []const u8,
    expected_filter: []const u8,
) Error!void {
    const argv = [_][]const u8{
        "nats",
        "--server",
        nats_url,
        "consumer",
        "info",
        stream_name,
        consumer_name,
        "--json",
    };

    var result = command.exec(allocator, io, &argv) catch {
        return error.NatsConsumerMissing;
    };
    defer result.deinit(allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("nats", result);
        return error.NatsConsumerMissing;
    }

    if (!consumerInfoFilterMatches(allocator, result.stdout, expected_filter)) {
        logging.err()
            .stringSafe("event", "nats_consumer_filter")
            .stringSafe("status", "error")
            .string("stream", stream_name)
            .string("consumer", consumer_name)
            .string("expected_filter", expected_filter)
            .log();
        return error.NatsConsumerFilterMismatch;
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
        filter_subject: ?[]const u8 = null,
    };
    const ConsumerInfo = struct {
        config: ConsumerConfig,
    };

    var parsed = std.json.parseFromSlice(ConsumerInfo, allocator, stdout, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();

    const actual = parsed.value.config.filter_subject orelse return false;
    return std.mem.eql(u8, actual, expected_filter);
}

fn streamInfoHasSubject(
    allocator: std.mem.Allocator,
    stdout: []const u8,
    expected_subject: []const u8,
) bool {
    const StreamConfig = struct {
        subjects: []const []const u8 = &.{},
    };
    const StreamInfo = struct {
        config: StreamConfig,
    };

    var parsed = std.json.parseFromSlice(StreamInfo, allocator, stdout, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();

    for (parsed.value.config.subjects) |subject| {
        if (subjectPatternMatches(subject, expected_subject)) return true;
    }
    return false;
}

fn subjectPatternMatches(pattern: []const u8, subject: []const u8) bool {
    if (std.mem.eql(u8, pattern, subject)) return true;

    var pattern_parts = std.mem.splitScalar(u8, pattern, '.');
    var subject_parts = std.mem.splitScalar(u8, subject, '.');

    while (pattern_parts.next()) |pattern_part| {
        if (std.mem.eql(u8, pattern_part, ">")) {
            return pattern_parts.next() == null and subject_parts.next() != null;
        }

        const subject_part = subject_parts.next() orelse return false;
        if (std.mem.eql(u8, pattern_part, "*")) continue;
        if (!std.mem.eql(u8, pattern_part, subject_part)) return false;
    }

    return subject_parts.next() == null;
}

test "consumerInfoFilterMatches validates consumer filter" {
    const json =
        \\{
        \\  "name": "oracle-worker-load",
        \\  "config": {
        \\    "filter_subject": "sync.oracle.load"
        \\  }
        \\}
    ;

    try std.testing.expect(consumerInfoFilterMatches(std.testing.allocator, json, "sync.oracle.load"));
    try std.testing.expect(!consumerInfoFilterMatches(std.testing.allocator, json, "wireless.audit"));
}

test "streamInfoHasSubject validates exact and wildcard subjects" {
    const json =
        \\{
        \\  "config": {
        \\    "subjects": ["sync.scan.request", "sync.oracle.load", "wireless.>"]
        \\  }
        \\}
    ;

    try std.testing.expect(streamInfoHasSubject(std.testing.allocator, json, "sync.oracle.load"));
    try std.testing.expect(streamInfoHasSubject(std.testing.allocator, json, "wireless.audit"));
    try std.testing.expect(!streamInfoHasSubject(std.testing.allocator, json, "sync.oracle.result"));
}

test "subjectPatternMatches follows NATS wildcard shape" {
    try std.testing.expect(subjectPatternMatches("sync.oracle.load", "sync.oracle.load"));
    try std.testing.expect(subjectPatternMatches("sync.*.load", "sync.oracle.load"));
    try std.testing.expect(subjectPatternMatches("sync.>", "sync.oracle.load"));
    try std.testing.expect(!subjectPatternMatches("sync.*.load", "sync.oracle.result"));
    try std.testing.expect(!subjectPatternMatches("sync.>", "sync"));
}
