const std = @import("std");
const builtin = @import("builtin");
const logging = @import("logging.zig");
const model = @import("state.zig");

const MAX_ACK_PAYLOAD_BYTES = 8 * 1024;
const NATS_IO_TIMEOUT_MS = 10_000;

pub const PublishMode = enum {
    core,
    jetstream_ack,
};

pub const Publisher = struct {
    allocator: std.mem.Allocator,
    published: std.ArrayListUnmanaged(model.Batch),

    pub fn init(allocator: std.mem.Allocator) !Publisher {
        return .{
            .allocator = allocator,
            .published = try std.ArrayListUnmanaged(model.Batch).initCapacity(allocator, 1),
        };
    }

    pub fn deinit(self: *Publisher) void {
        self.published.deinit(self.allocator);
    }

    pub fn publishBatch(self: *Publisher, batch: model.Batch) !void {
        try self.published.append(self.allocator, batch);
    }
};

const Endpoint = struct {
    host: []const u8,
    port: u16,
    user: ?[]const u8,
    pass: ?[]const u8,
    token: ?[]const u8,
    tls: bool,

    fn parse(nats_url: []const u8) !Endpoint {
        const trimmed = std.mem.trim(u8, nats_url, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidNatsUrl;

        const tls, const without_scheme = if (std.mem.startsWith(u8, trimmed, "tls://"))
            .{ true, trimmed["tls://".len..] }
        else if (std.mem.startsWith(u8, trimmed, "nats://"))
            .{ false, trimmed["nats://".len..] }
        else
            .{ false, trimmed };

        const authority = blk: {
            var iterator = std.mem.splitScalar(u8, without_scheme, '/');
            break :blk iterator.first();
        };
        if (authority.len == 0) return error.InvalidNatsUrl;

        var host_port = authority;
        var user: ?[]const u8 = null;
        var pass: ?[]const u8 = null;
        var token: ?[]const u8 = null;
        if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
            const userinfo = authority[0..at];
            host_port = authority[at + 1 ..];
            if (userinfo.len == 0 or host_port.len == 0) return error.InvalidNatsUrl;
            if (std.mem.indexOfScalar(u8, userinfo, ':')) |separator| {
                user = userinfo[0..separator];
                pass = userinfo[separator + 1 ..];
            } else {
                token = userinfo;
            }
        }

        const host, const port = try parseHostPort(host_port);
        return .{
            .host = host,
            .port = port,
            .user = user,
            .pass = pass,
            .token = token,
            .tls = tls,
        };
    }
};

pub fn publish(
    allocator: std.mem.Allocator,
    io: std.Io,
    nats_url: []const u8,
    subject: []const u8,
    payload: []const u8,
    mode: PublishMode,
    timeout_ms: u32,
) !void {
    _ = allocator;
    const effective_timeout_ms = if (timeout_ms == 0) NATS_IO_TIMEOUT_MS else timeout_ms;
    const endpoint = try Endpoint.parse(nats_url);
    if (endpoint.tls) return error.UnsupportedNatsScheme;
    try validateSubject(subject);

    switch (mode) {
        .core => try publishCore(io, endpoint, subject, payload, effective_timeout_ms),
        .jetstream_ack => try publishJetStreamAckOnce(io, endpoint, subject, payload, effective_timeout_ms),
    }
}

fn publishCore(
    io: std.Io,
    endpoint: Endpoint,
    subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) !void {
    var stream = try connectEndpoint(endpoint, io);
    defer stream.close(io);
    try applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try expectInfo(&reader);
    try writeConnect(&writer.interface, endpoint);
    try writeCorePublish(&writer.interface, subject, payload);
    try writePing(&writer.interface);
    try waitForPong(&reader, &writer);
}

fn publishJetStreamAckOnce(
    io: std.Io,
    endpoint: Endpoint,
    subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) !void {
    var stream = try connectEndpoint(endpoint, io);
    defer stream.close(io);
    try applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try expectInfo(&reader);
    try writeConnect(&writer.interface, endpoint);

    var inbox_buffer: [64]u8 = undefined;
    const inbox = try makeAckInbox(io, &inbox_buffer);
    try writeAckSubscription(&writer.interface, inbox);
    try writeAckedPublish(&writer.interface, subject, inbox, payload);
    try waitForPublishAck(io, &reader, &writer, timeout_ms);
}

fn parseHostPort(host_port: []const u8) !struct { []const u8, u16 } {
    if (host_port.len == 0) return error.InvalidNatsUrl;

    if (host_port[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host_port, ']') orelse return error.InvalidNatsUrl;
        const host = host_port[1..close];
        if (host.len == 0) return error.InvalidNatsUrl;
        if (close + 1 == host_port.len) return .{ host, 4222 };
        if (host_port[close + 1] != ':') return error.InvalidNatsUrl;
        return .{ host, try parsePort(host_port[close + 2 ..]) };
    }

    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |separator| {
        const host = host_port[0..separator];
        if (host.len == 0) return error.InvalidNatsUrl;
        return .{ host, try parsePort(host_port[separator + 1 ..]) };
    }

    return .{ host_port, 4222 };
}

fn parsePort(raw: []const u8) !u16 {
    if (raw.len == 0) return error.InvalidNatsUrl;
    return std.fmt.parseInt(u16, raw, 10) catch error.InvalidNatsUrl;
}

fn applySocketTimeouts(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;

    const timeout = std.posix.timeval{
        .sec = @intCast(@divTrunc(timeout_ms, 1_000)),
        .usec = @intCast(@mod(timeout_ms, 1_000) * 1_000),
    };
    const timeout_bytes = std.mem.asBytes(&timeout);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, timeout_bytes);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, timeout_bytes);
}

fn connectEndpoint(endpoint: Endpoint, io: std.Io) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(endpoint.host, endpoint.port)) |address| {
        return address.connect(io, .{ .mode = .stream });
    } else |_| {}

    try std.Io.net.HostName.validate(endpoint.host);
    return std.Io.net.HostName.connect(
        .{ .bytes = endpoint.host },
        io,
        endpoint.port,
        .{ .mode = .stream },
    );
}

fn validateSubject(subject: []const u8) !void {
    if (subject.len == 0) return error.InvalidSubject;
    for (subject) |byte| {
        if (std.ascii.isWhitespace(byte)) return error.InvalidSubject;
    }
}

fn expectInfo(reader: *std.Io.net.Stream.Reader) !void {
    const line = try readLine(reader);
    if (!std.mem.startsWith(u8, line, "INFO ")) return error.ProtocolError;
}

fn writeConnect(writer: *std.Io.Writer, endpoint: Endpoint) !void {
    try writer.writeAll("CONNECT ");
    try writeConnectJson(writer, endpoint.user, endpoint.pass, endpoint.token);
    try writer.writeAll("\r\n");
    try writer.flush();
}

fn writeConnectJson(
    writer: *std.Io.Writer,
    user: ?[]const u8,
    pass: ?[]const u8,
    token: ?[]const u8,
) !void {
    try writer.writeAll("{\"verbose\":false,\"pedantic\":false");
    if (user) |value| {
        try writer.writeAll(",\"user\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    if (pass) |value| {
        try writer.writeAll(",\"pass\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    if (token) |value| {
        try writer.writeAll(",\"auth_token\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    try writer.writeAll("}");
}

fn writeCorePublish(writer: *std.Io.Writer, subject: []const u8, payload: []const u8) !void {
    try writer.print("PUB {s} {d}\r\n", .{ subject, payload.len });
    try writer.writeAll(payload);
    try writer.writeAll("\r\n");
    try writer.flush();
}

fn writePing(writer: *std.Io.Writer) !void {
    try writer.writeAll("PING\r\n");
    try writer.flush();
}

fn makeAckInbox(io: std.Io, buffer: []u8) ![]const u8 {
    var random: [12]u8 = undefined;
    io.random(&random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    return std.fmt.bufPrint(
        buffer,
        "_INBOX.zig-coordinator.{s}",
        .{&random_hex},
    );
}

fn writeAckSubscription(writer: *std.Io.Writer, inbox: []const u8) !void {
    try writer.print("SUB {s} 1\r\n", .{inbox});
}

fn writeAckedPublish(
    writer: *std.Io.Writer,
    subject: []const u8,
    inbox: []const u8,
    payload: []const u8,
) !void {
    try writer.print("PUB {s} {s} {d}\r\n", .{ subject, inbox, payload.len });
    try writer.writeAll(payload);
    try writer.writeAll("\r\n");
    try writer.flush();
}

fn waitForPong(reader: *std.Io.net.Stream.Reader, writer: *std.Io.net.Stream.Writer) !void {
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        const line = readLine(reader) catch |err| return err;
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.startsWith(u8, line, "INFO ")) {
            continue;
        }
        if (std.mem.eql(u8, line, "PONG")) {
            return;
        }
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }

        return error.ProtocolError;
    }

    return error.PublishAckFailed;
}

fn waitForPublishAck(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    timeout_ms: u32,
) !void {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        if (elapsedMs(start_ts, io) >= timeout_ms) {
            logPublishAckFailure("ack_timeout", "timed out waiting for JetStream publish acknowledgement");
            return error.PublishAckFailed;
        }

        const line = readLine(reader) catch |err| {
            if (err == error.Timeout) {
                logPublishAckFailure("ack_timeout", "timed out waiting for JetStream publish acknowledgement");
                return error.PublishAckFailed;
            }
            return err;
        };
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            logPublishAckProgress("publish_ack", line);
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.eql(u8, line, "PONG") or std.mem.startsWith(u8, line, "INFO ")) {
            logPublishAckProgress("publish_ack", line);
            continue;
        }
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }
        if (std.mem.startsWith(u8, line, "MSG ")) {
            logPublishAckProgress("publish_ack", line);
            const payload_size = try parseMessageSize(line);
            if (payload_size > MAX_ACK_PAYLOAD_BYTES) return error.PublishAckTooLarge;
            const payload = try takeBytes(reader, payload_size);
            const has_error = std.mem.indexOf(u8, payload, "\"error\"") != null;
            const terminator = try takeArray2(reader);
            if (!std.mem.eql(u8, terminator, "\r\n")) return error.ProtocolError;
            if (has_error) {
                logPublishAckFailure("ack_error", payload);
                return error.PublishAckFailed;
            }
            logPublishAckSuccess(attempts + 1);
            return;
        }

        return error.ProtocolError;
    }

    logPublishAckFailure("ack_timeout", "no JetStream publish acknowledgement received");
    return error.PublishAckFailed;
}

fn elapsedMs(start_ts: std.Io.Timestamp, io: std.Io) u32 {
    const elapsed_ms = start_ts.untilNow(io, .awake).toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(@min(elapsed_ms, std.math.maxInt(u32)));
}

fn readLine(reader: *std.Io.net.Stream.Reader) ![]const u8 {
    const raw = reader.interface.takeDelimiterExclusive('\n') catch |err| return mapReadError(reader, err);
    return std.mem.trim(u8, raw, " \t\r");
}

fn takeBytes(reader: *std.Io.net.Stream.Reader, size: usize) ![]const u8 {
    return reader.interface.take(size) catch |err| mapReadError(reader, err);
}

fn takeArray2(reader: *std.Io.net.Stream.Reader) !*[2]u8 {
    return reader.interface.takeArray(2) catch |err| mapReadError(reader, err);
}

fn mapReadError(reader: *std.Io.net.Stream.Reader, err: anyerror) anyerror {
    if (reader.err) |read_error| {
        if (read_error == error.Timeout) return error.Timeout;
    }
    return err;
}

fn parseMessageSize(line: []const u8) !usize {
    var parts = std.mem.splitBackwardsScalar(u8, line, ' ');
    const size_token = parts.first();
    if (size_token.len == 0) return error.ProtocolError;
    return std.fmt.parseInt(usize, size_token, 10) catch error.ProtocolError;
}

fn logPublishAckFailure(reason: []const u8, raw: []const u8) void {
    var buffer: [1024]u8 = undefined;
    const snippet = sanitizeSnippet(&buffer, raw);
    logging.err()
        .stringSafe("event", "jetstream_publish_ack")
        .stringSafe("status", "error")
        .string("reason", reason)
        .string("payload", snippet)
        .log();
}

fn logPublishAckProgress(phase: []const u8, raw: []const u8) void {
    var buffer: [1024]u8 = undefined;
    const snippet = sanitizeSnippet(&buffer, raw);
    logging.debug()
        .stringSafe("event", "jetstream_publish_ack")
        .stringSafe("status", "observed")
        .string("phase", phase)
        .string("payload", snippet)
        .log();
}

fn logPublishAckSuccess(attempts: usize) void {
    logging.debug()
        .stringSafe("event", "jetstream_publish_ack")
        .stringSafe("status", "ok")
        .stringSafe("phase", "publish_ack")
        .int("attempts", attempts)
        .log();
}

fn sanitizeSnippet(buffer: []u8, raw: []const u8) []const u8 {
    var in_index: usize = 0;
    var out_index: usize = 0;

    while (in_index < raw.len and out_index < buffer.len) : (in_index += 1) {
        const byte = raw[in_index];
        buffer[out_index] = switch (byte) {
            '\n', '\r', '\t' => ' ',
            else => byte,
        };
        out_index += 1;
    }

    return std.mem.trim(u8, buffer[0..out_index], " ");
}

fn requestJetStreamApi(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: Endpoint,
    api_subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) ![]u8 {
    var stream = try connectEndpoint(endpoint, io);
    defer stream.close(io);
    try applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try expectInfo(&reader);
    try writeConnect(&writer.interface, endpoint);

    var inbox_buffer: [64]u8 = undefined;
    const inbox = try makeAckInbox(io, &inbox_buffer);
    try writeAckSubscription(&writer.interface, inbox);
    try writeAckedPublish(&writer.interface, api_subject, inbox, payload);

    return readMessagePayloadAlloc(allocator, io, &reader, &writer, timeout_ms);
}

fn readMessagePayloadAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    timeout_ms: u32,
) ![]u8 {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        if (elapsedMs(start_ts, io) >= timeout_ms) return error.Timeout;

        const line = try readLine(reader);
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.eql(u8, line, "PONG") or std.mem.startsWith(u8, line, "INFO ")) {
            continue;
        }
        if (std.mem.startsWith(u8, line, "-ERR")) return error.ServerError;
        if (std.mem.startsWith(u8, line, "MSG ")) {
            const payload_size = try parseMessageSize(line);
            if (payload_size > MAX_ACK_PAYLOAD_BYTES) return error.PublishAckTooLarge;
            const message = try takeBytes(reader, payload_size);
            const owned = try allocator.dupe(u8, message);
            errdefer allocator.free(owned);
            const terminator = try takeArray2(reader);
            if (!std.mem.eql(u8, terminator, "\r\n")) return error.ProtocolError;
            return owned;
        }

        return error.ProtocolError;
    }

    return error.Timeout;
}

test "parse endpoint defaults port and extracts auth" {
    const endpoint = try Endpoint.parse("nats://user:pass@nats:4222");
    try std.testing.expectEqualStrings("nats", endpoint.host);
    try std.testing.expectEqual(@as(u16, 4222), endpoint.port);
    try std.testing.expectEqualStrings("user", endpoint.user.?);
    try std.testing.expectEqualStrings("pass", endpoint.pass.?);
    try std.testing.expect(endpoint.token == null);
    try std.testing.expect(!endpoint.tls);
}

test "parse endpoint treats bare userinfo as token" {
    const endpoint = try Endpoint.parse("nats://token@nats");
    try std.testing.expectEqualStrings("nats", endpoint.host);
    try std.testing.expectEqualStrings("token", endpoint.token.?);
    try std.testing.expect(endpoint.user == null);
    try std.testing.expect(endpoint.pass == null);
}

test "parse endpoint handles implicit port and tls scheme" {
    const endpoint = try Endpoint.parse("tls://nats.internal");
    try std.testing.expectEqualStrings("nats.internal", endpoint.host);
    try std.testing.expectEqual(@as(u16, 4222), endpoint.port);
    try std.testing.expect(endpoint.tls);
}

test "validate subject rejects protocol separators" {
    try validateSubject("sync.oracle.load");
    try std.testing.expectError(error.InvalidSubject, validateSubject("sync.oracle.load\r\nPING"));
}

test "write connect json escapes credentials" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeConnectJson(&writer, "user", "p\nx", null);
    try std.testing.expectEqualStrings(
        "{\"verbose\":false,\"pedantic\":false,\"user\":\"user\",\"pass\":\"p\\nx\"}",
        writer.buffered(),
    );
}

test "write connect json emits auth token" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeConnectJson(&writer, null, null, "token");
    try std.testing.expectEqualStrings(
        "{\"verbose\":false,\"pedantic\":false,\"auth_token\":\"token\"}",
        writer.buffered(),
    );
}

test "write core publish does not request a JetStream ack" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeCorePublish(&writer, "wireless.backlog.list.reply", "{\"ok\":true}");
    try std.testing.expectEqualStrings(
        "PUB wireless.backlog.list.reply 11\r\n{\"ok\":true}\r\n",
        writer.buffered(),
    );
}

test "write ack subscription and publish use explicit inbox reply" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeAckSubscription(&writer, "_INBOX.zig-coordinator.abc123");
    try writeAckedPublish(&writer, "sync.oracle.load", "_INBOX.zig-coordinator.abc123", "{\"batch_id\":\"b\"}");
    try std.testing.expectEqualStrings(
        "SUB _INBOX.zig-coordinator.abc123 1\r\n" ++
            "PUB sync.oracle.load _INBOX.zig-coordinator.abc123 16\r\n" ++
            "{\"batch_id\":\"b\"}\r\n",
        writer.buffered(),
    );
}

test "parse message size uses final token" {
    try std.testing.expectEqual(@as(usize, 42), try parseMessageSize("MSG _INBOX.x 1 42"));
    try std.testing.expectEqual(@as(usize, 42), try parseMessageSize("MSG _INBOX.x 1 reply.to 42"));
}

test "JetStream publish round-trip when NATS_URL is set" {
    const raw_url = if (std.c.getenv("NATS_URL")) |value| std.mem.span(value) else return error.SkipZigTest;
    const endpoint = try Endpoint.parse(raw_url);
    if (endpoint.tls) return error.SkipZigTest;

    const seed: u64 = @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(std.testing.io, .awake).toNanoseconds())));
    var prng = std.Random.DefaultPrng.init(seed);
    var random_bytes: [8]u8 = undefined;
    prng.random().bytes(&random_bytes);
    const random_hex = std.fmt.bytesToHex(random_bytes, .lower);

    var stream_buffer: [64]u8 = undefined;
    const stream_name = try std.fmt.bufPrint(&stream_buffer, "NATS_RELIABILITY_TEST_{s}", .{&random_hex});
    var subject_buffer: [96]u8 = undefined;
    const subject = try std.fmt.bufPrint(&subject_buffer, "nats.reliability.test.{s}", .{&random_hex});
    const payload = "{\"ok\":true}";
    const timeout_ms: u32 = 2_000;

    const create_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"name\":\"{s}\",\"subjects\":[\"{s}\"],\"storage\":\"memory\",\"retention\":\"limits\",\"max_msgs\":100}}",
        .{ stream_name, subject },
    );
    defer std.testing.allocator.free(create_payload);

    var create_subject_buffer: [96]u8 = undefined;
    const create_subject = try std.fmt.bufPrint(&create_subject_buffer, "$JS.API.STREAM.CREATE.{s}", .{stream_name});
    const create_response = try requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, create_subject, create_payload, timeout_ms);
    defer std.testing.allocator.free(create_response);
    try std.testing.expect(std.mem.indexOf(u8, create_response, "\"error\"") == null);

    var delete_subject_buffer: [96]u8 = undefined;
    const delete_subject = try std.fmt.bufPrint(&delete_subject_buffer, "$JS.API.STREAM.DELETE.{s}", .{stream_name});
    defer {
        const delete_response = requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, delete_subject, "{}", timeout_ms) catch null;
        if (delete_response) |response| std.testing.allocator.free(response);
    }

    const publish_started_ts = std.Io.Timestamp.now(std.testing.io, .awake);
    try publish(std.testing.allocator, std.testing.io, raw_url, subject, payload, .jetstream_ack, timeout_ms);
    try std.testing.expect(elapsedMs(publish_started_ts, std.testing.io) <= timeout_ms);

    const get_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"last_by_subj\":\"{s}\"}}",
        .{subject},
    );
    defer std.testing.allocator.free(get_payload);

    var get_subject_buffer: [96]u8 = undefined;
    const get_subject = try std.fmt.bufPrint(&get_subject_buffer, "$JS.API.STREAM.MSG.GET.{s}", .{stream_name});
    const get_response = try requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, get_subject, get_payload, timeout_ms);
    defer std.testing.allocator.free(get_response);

    var encoded_payload_buffer: [std.base64.standard.Encoder.calcSize(payload.len)]u8 = undefined;
    const encoded_payload = std.base64.standard.Encoder.encode(&encoded_payload_buffer, payload);
    try std.testing.expect(std.mem.indexOf(u8, get_response, subject) != null);
    try std.testing.expect(std.mem.indexOf(u8, get_response, encoded_payload) != null);
}
