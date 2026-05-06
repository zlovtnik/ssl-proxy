const std = @import("std");
const logging = @import("logging.zig");
const model = @import("state.zig");

const MAX_ACK_PAYLOAD_BYTES = 8 * 1024;

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
) !void {
    _ = allocator;
    const endpoint = try Endpoint.parse(nats_url);
    if (endpoint.tls) return error.UnsupportedNatsScheme;
    try validateSubject(subject);

    var stream = try connectEndpoint(endpoint, io);
    defer stream.close(io);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try expectInfo(&reader.interface);
    try writeConnect(&writer.interface, endpoint);
    switch (mode) {
        .core => try writeCorePublish(&writer.interface, subject, payload),
        .jetstream_ack => {
            try writeAckedPublish(io, &reader.interface, &writer.interface, subject, payload);
            try waitForPublishAck(&reader.interface, &writer.interface);
        },
    }
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

fn expectInfo(reader: *std.Io.Reader) !void {
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

fn writeAckedPublish(
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    subject: []const u8,
    payload: []const u8,
) !void {
    var random: [12]u8 = undefined;
    io.random(&random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    var inbox_buffer: [64]u8 = undefined;
    const inbox = try std.fmt.bufPrint(
        &inbox_buffer,
        "_INBOX.zig-coordinator.{s}",
        .{&random_hex},
    );

    try writer.print("SUB {s} 1\r\nPING\r\n", .{inbox});
    try writer.flush();
    try waitForPong(reader, writer);

    try writer.print("PUB {s} {s} {d}\r\n", .{ subject, inbox, payload.len });
    try writer.writeAll(payload);
    try writer.writeAll("\r\n");
    try writer.flush();
}

fn waitForPong(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        const line = try readLine(reader);
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.writeAll("PONG\r\n");
            try writer.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.startsWith(u8, line, "INFO ")) {
            continue;
        }
        if (std.mem.eql(u8, line, "PONG")) return;
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }

        return error.ProtocolError;
    }

    logPublishAckFailure("subscribe_ready_timeout", "no PONG received after ACK inbox subscription");
    return error.PublishAckFailed;
}

fn waitForPublishAck(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        const line = try readLine(reader);
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.writeAll("PONG\r\n");
            try writer.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.startsWith(u8, line, "INFO ")) {
            continue;
        }
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }
        if (std.mem.startsWith(u8, line, "MSG ")) {
            const payload_size = try parseMessageSize(line);
            if (payload_size > MAX_ACK_PAYLOAD_BYTES) return error.PublishAckTooLarge;
            const payload = try reader.take(payload_size);
            const has_error = std.mem.indexOf(u8, payload, "\"error\"") != null;
            const terminator = try reader.takeArray(2);
            if (!std.mem.eql(u8, terminator, "\r\n")) return error.ProtocolError;
            if (has_error) {
                logPublishAckFailure("ack_error", payload);
                return error.PublishAckFailed;
            }
            return;
        }

        return error.ProtocolError;
    }

    logPublishAckFailure("ack_timeout", "no JetStream publish acknowledgement received");
    return error.PublishAckFailed;
}

fn readLine(reader: *std.Io.Reader) ![]const u8 {
    const raw = try reader.takeDelimiterExclusive('\n');
    return std.mem.trim(u8, raw, " \t\r");
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

test "parse message size uses final token" {
    try std.testing.expectEqual(@as(usize, 42), try parseMessageSize("MSG _INBOX.x 1 42"));
    try std.testing.expectEqual(@as(usize, 42), try parseMessageSize("MSG _INBOX.x 1 reply.to 42"));
}
